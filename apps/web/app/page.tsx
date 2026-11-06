import { MOCK_GARAGE } from "@/lib/mock";

export default function GaragePage() {
  const { vehicle, keys, latestEvent } = MOCK_GARAGE;

  return (
    <div className="space-y-6">
      <div role="status" className="rounded-md border border-warn-fg/40 bg-warn-bg px-4 py-3 text-sm text-warn-fg">
        <strong>MOCK STATE: not backend-verified.</strong> This screen shows placeholder data. Lock state will
        only change after the backend verifies a signed challenge (Sprint 3).
      </div>

      <h1 className="text-2xl font-semibold">Garage</h1>

      <section aria-labelledby="vehicle-heading" className="rounded-lg border border-line bg-panel p-6">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <h2 id="vehicle-heading" className="text-lg font-medium">
              {vehicle.name}
            </h2>
            <p className="mt-1 text-sm text-muted">Virtual vehicle</p>
          </div>
          <p className="text-sm">
            Lock state: <span className="font-semibold uppercase">{vehicle.lockState}</span>{" "}
            <span className="text-muted">(mock)</span>
          </p>
        </div>

        <dl className="mt-6 grid gap-4 text-sm sm:grid-cols-2">
          <div>
            <dt className="text-muted">Digital keys</dt>
            <dd>{keys.length === 0 ? "No keys enrolled (mock)" : `${keys.length} enrolled`}</dd>
          </div>
          <div>
            <dt className="text-muted">Latest event</dt>
            <dd>{latestEvent ?? "None yet (mock)"}</dd>
          </div>
        </dl>

        <div className="mt-6 flex flex-wrap gap-3">
          {(["Request unlock", "Request lock"] as const).map((label) => (
            <button
              key={label}
              type="button"
              disabled
              aria-describedby="actions-note"
              className="rounded-md border border-line px-4 py-2 text-sm text-muted disabled:cursor-not-allowed"
            >
              {label}
            </button>
          ))}
        </div>
        <p id="actions-note" className="mt-2 text-xs text-muted">
          Disabled until key enrollment (Sprint 2) and backend authentication (Sprint 3) exist.
        </p>
      </section>
    </div>
  );
}
