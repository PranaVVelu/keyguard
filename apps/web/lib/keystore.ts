// Browser key lifecycle (docs/DECISIONS.md D-007). IndexedDB can store a non-extractable
// CryptoKey directly, so the key survives page refreshes without its bytes ever being readable.

const DB_NAME = "keyguard";
const STORE = "device-keys";

export interface StoredKey {
  keyId: string;
  labId: string;
  privateKey: CryptoKey;
  fingerprint: string;
  createdAt: number;
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

/** Delete keys belonging to any other lab. Old labs are unreachable once their session token is gone. */
export async function purgeOtherLabs(labId: string): Promise<void> {
  const all = await run("readonly", (s) => s.getAll() as IDBRequest<StoredKey[]>);
  for (const k of all) {
    if (k.labId !== labId) await run("readwrite", (s) => s.delete(k.keyId));
  }
}
