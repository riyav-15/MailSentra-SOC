export default function Notice({ children, tone = "info" }) {
  const styles =
    tone === "error"
      ? "border-red-400/30 bg-red-400/10 text-red-100"
      : "border-line bg-panelSoft text-slate-300";

  return (
    <p className={`rounded-md border p-3 text-sm ${styles}`}>
      {children}
    </p>
  );
}
