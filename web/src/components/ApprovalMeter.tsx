/**
 * Width comes from one of a fixed ladder of classes rather than a computed
 * inline `style` width, which the CSP would strip. Approvals are a small
 * integer ratio, so five steps land on the exact value in every realistic
 * case and round to the nearest step beyond that.
 */
export function ApprovalMeter({ approvals, required }: { approvals: number; required: number }) {
  const ratio = required > 0 ? Math.min(approvals / required, 1) : 0;
  const step = Math.round(ratio * 5);

  return (
    <div className="meter">
      <div className="meter-track">
        <div className={`meter-fill meter-${step}`} />
      </div>
      <span>
        {approvals} of {required} {required === 1 ? "approval" : "approvals"}
      </span>
    </div>
  );
}
