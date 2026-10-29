import React from "react";

export function AuthAckModal({
  target,
  onConfirm,
  onCancel,
}: {
  target: string;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  return (
    <div className="modal-overlay" onClick={onCancel}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <h2>Authorization required</h2>
        <p>
          Active scanning sends real probe requests (including bounded DoS, injection and CSRF checks) to the target
          below. Only continue if you own this endpoint or have explicit written authorization to test it.
        </p>
        <p className="mono" style={{ color: "var(--accent-2)", marginTop: 10 }}>
          {target}
        </p>
        <p style={{ marginTop: 14 }}>
          Unauthorized testing may be illegal. All probes are rate-bounded, but you are responsible for having
          permission.
        </p>
        <div className="row" style={{ marginTop: 22, justifyContent: "flex-end" }}>
          <button className="btn ghost" onClick={onCancel}>
            Cancel
          </button>
          <button className="btn primary" onClick={onConfirm}>
            I am authorized — run scan ▶
          </button>
        </div>
      </div>
    </div>
  );
}
