export default function FilterBar({ value, onChange, options }) {
  return (
    <div className="filter-bar">
      <label htmlFor="port-select">Filter port:</label>
      <select
        id="port-select"
        value={value}
        onChange={e => onChange(e.target.value)}
      >
        {options.map(opt => (
          <option key={opt.value} value={opt.value}>{opt.label}</option>
        ))}
      </select>
    </div>
  );
}
