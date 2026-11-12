// Browser key lifecycle (docs/DECISIONS.md D-007). IndexedDB can store a non-extractable
// CryptoKey directly, so the key survives page refreshes without its bytes ever being readable.

const DB_NAME = "keyguard";
const STORE = "device-keys";

export type CredentialType = "phone" | "card" | "fob";

export interface StoredKey {
  keyId: string;
  labId: string;
  privateKey: CryptoKey;
  fingerprint: string;
  createdAt: number;
  credentialType?: CredentialType; // absent on keys saved before Sprint 9 → "phone"
  counter?: number; // kg-fob-v1 only: last counter this fob used (D-010)
}

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => {
      const store = req.result.createObjectStore(STORE, { keyPath: "keyId" });
      store.createIndex("labId", "labId");
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function run<T>(mode: IDBTransactionMode, fn: (store: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  const db = await openDb();
  try {
    return await new Promise<T>((resolve, reject) => {
      const tx = db.transaction(STORE, mode);
      const req = fn(tx.objectStore(STORE));
      tx.oncomplete = () => resolve(req.result);
      tx.onerror = () => reject(tx.error);
      tx.onabort = () => reject(tx.error);
    });
  } finally {
    db.close();
  }
}

export function saveKey(key: StoredKey): Promise<IDBValidKey> {
  return run("readwrite", (s) => s.put(key));
}

export function getKey(keyId: string): Promise<StoredKey | undefined> {
  return run("readonly", (s) => s.get(keyId) as IDBRequest<StoredKey | undefined>);
}

export function listKeysForLab(labId: string): Promise<StoredKey[]> {
  return run("readonly", (s) => s.index("labId").getAll(labId) as IDBRequest<StoredKey[]>);
}

/**
 * Delete keys belonging to any other lab, except labs saved to the signed-in account (`keep`, D-012).
 * An unsaved lab is unreachable once its session token is gone, so its keys are useless.
 */
export async function purgeOtherLabs(labId: string, keep: readonly string[] = []): Promise<void> {
  const all = await run("readonly", (s) => s.getAll() as IDBRequest<StoredKey[]>);
  for (const k of all) {
    if (k.labId !== labId && !keep.includes(k.labId)) await run("readwrite", (s) => s.delete(k.keyId));
  }
}

/**
 * Reserve the next kg-fob-v1 counter for a fob, persisting it BEFORE anything is signed or sent (D-010).
 * Read-increment-write happens in one IndexedDB transaction, so two tabs can never reserve the same counter,
 * and a crash after this point burns a counter instead of reusing one.
 */
export async function reserveFobCounter(keyId: string): Promise<number> {
  const db = await openDb();
  try {
    return await new Promise<number>((resolve, reject) => {
      const tx = db.transaction(STORE, "readwrite");
      const store = tx.objectStore(STORE);
      let next = 0;
      const get = store.get(keyId);
      get.onsuccess = () => {
        const rec = get.result as StoredKey | undefined;
        if (!rec || rec.credentialType !== "fob") {
          tx.abort();
          return;
        }
        next = (rec.counter ?? 0) + 1;
        store.put({ ...rec, counter: next });
      };
      tx.oncomplete = () => resolve(next);
      tx.onerror = () => reject(tx.error);
      tx.onabort = () => reject(tx.error ?? new Error("Not a fob stored in this browser"));
    });
  } finally {
    db.close();
  }
}
