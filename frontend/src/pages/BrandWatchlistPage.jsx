import { Plus, Save, Trash2 } from "lucide-react";
import { useEffect, useState } from "react";
import Notice from "../components/Notice";
import { api, apiError } from "../services/api";

const emptyForm = {
  brand_name: "",
  legitimate_domains: "",
  keywords: "",
  logo_hint: ""
};

export default function BrandWatchlistPage() {
  const [brands, setBrands] = useState([]);
  const [form, setForm] = useState(emptyForm);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");

  async function loadBrands() {
    setError("");
    try {
      const response = await api.get("/admin/brand-watchlist");
      setBrands(response.data);
    } catch (err) {
      setError(apiError(err));
    }
  }

  useEffect(() => {
    loadBrands();
  }, []);

  async function createBrand(event) {
    event.preventDefault();
    setError("");
    setMessage("");
    try {
      await api.post("/admin/brand-watchlist", serializeForm(form));
      setForm(emptyForm);
      setMessage("Brand added to watchlist.");
      await loadBrands();
    } catch (err) {
      setError(apiError(err));
    }
  }

  async function updateBrand(brand) {
    setError("");
    setMessage("");
    try {
      await api.patch(`/admin/brand-watchlist/${brand.id}`, {
        brand_name: brand.brand_name,
        legitimate_domains: brand.legitimate_domains,
        keywords: brand.keywords,
        logo_hint: brand.logo_hint || ""
      });
      setMessage("Brand watchlist updated.");
      await loadBrands();
    } catch (err) {
      setError(apiError(err));
    }
  }

  async function deleteBrand(brandId) {
    setError("");
    setMessage("");
    try {
      await api.delete(`/admin/brand-watchlist/${brandId}`);
      setMessage("Brand removed.");
      await loadBrands();
    } catch (err) {
      setError(apiError(err));
    }
  }

  function patchBrand(id, field, value) {
    setBrands((items) => items.map((item) => (item.id === id ? { ...item, [field]: value } : item)));
  }

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-semibold text-white">Brand Watchlist</h1>
        <p className="mt-1 text-sm text-slate-400">Manage legitimate domains and keywords used for impersonation detection.</p>
      </header>

      {error ? <Notice tone="error">{error}</Notice> : null}
      {message ? <Notice>{message}</Notice> : null}

      <form onSubmit={createBrand} className="rounded-lg border border-line bg-panel p-5 shadow-glow">
        <h2 className="text-sm font-semibold text-slate-200">Add Brand</h2>
        <div className="mt-4 grid gap-4 md:grid-cols-2">
          <Input label="Brand name" value={form.brand_name} onChange={(value) => setForm({ ...form, brand_name: value })} />
          <Input label="Logo hint" value={form.logo_hint} onChange={(value) => setForm({ ...form, logo_hint: value })} />
          <Input label="Legitimate domains" value={form.legitimate_domains} onChange={(value) => setForm({ ...form, legitimate_domains: value })} />
          <Input label="Keywords" value={form.keywords} onChange={(value) => setForm({ ...form, keywords: value })} />
        </div>
        <button className="btn-primary mt-4" type="submit">
          <Plus size={16} />
          Add brand
        </button>
      </form>

      <section className="grid gap-4 xl:grid-cols-2">
        {brands.map((brand) => (
          <article key={brand.id} className="rounded-lg border border-line bg-panel p-5 shadow-glow">
            <div className="grid gap-4 md:grid-cols-2">
              <Input label="Brand name" value={brand.brand_name} onChange={(value) => patchBrand(brand.id, "brand_name", value)} />
              <Input label="Logo hint" value={brand.logo_hint || ""} onChange={(value) => patchBrand(brand.id, "logo_hint", value)} />
              <ListInput label="Legitimate domains" values={brand.legitimate_domains || []} onChange={(values) => patchBrand(brand.id, "legitimate_domains", values)} />
              <ListInput label="Keywords" values={brand.keywords || []} onChange={(values) => patchBrand(brand.id, "keywords", values)} />
            </div>
            <div className="mt-4 flex flex-wrap gap-2">
              <button className="btn-secondary" type="button" onClick={() => updateBrand(brand)}>
                <Save size={16} />
                Save
              </button>
              <button className="btn-secondary" type="button" onClick={() => deleteBrand(brand.id)}>
                <Trash2 size={16} />
                Delete
              </button>
            </div>
          </article>
        ))}
      </section>
    </div>
  );
}

function Input({ label, value, onChange }) {
  return (
    <label className="text-sm font-medium text-slate-300">
      {label}
      <input className="input mt-2" value={value} onChange={(event) => onChange(event.target.value)} />
    </label>
  );
}

function ListInput({ label, values, onChange }) {
  return (
    <label className="text-sm font-medium text-slate-300">
      {label}
      <input className="input mt-2" value={values.join(", ")} onChange={(event) => onChange(parseList(event.target.value))} />
    </label>
  );
}

function serializeForm(form) {
  return {
    brand_name: form.brand_name,
    legitimate_domains: parseList(form.legitimate_domains),
    keywords: parseList(form.keywords),
    logo_hint: form.logo_hint
  };
}

function parseList(value) {
  return value.split(",").map((item) => item.trim()).filter(Boolean);
}
