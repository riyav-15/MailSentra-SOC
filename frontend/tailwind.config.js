export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        surface: "#08111f",
        panel: "#0d1728",
        panelSoft: "#101d31",
        line: "#1f334c",
        cyan: "#22d3ee",
        success: "#22c55e",
        warning: "#f59e0b",
        danger: "#ef4444"
      },
      boxShadow: {
        glow: "0 0 0 1px rgba(34, 211, 238, 0.12), 0 20px 60px rgba(0, 0, 0, 0.35)"
      }
    }
  },
  plugins: []
};
