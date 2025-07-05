export default function PacketTable({ packets }) {
  return (
    <div className="table-container">
      <table>
        <thead>
          <tr>
            <th>Protocol</th>
            <th>Source</th>
            <th>Destination</th>
            <th>Payload</th>
          </tr>
        </thead>
        <tbody>
          {packets.map((p, i) => (
            <tr key={i}>
              <td>{p.protocol}</td>
              <td>{p.src_ip}:{p.src_port}</td>
              <td>{p.dest_ip}:{p.dest_port}</td>
              <td><pre>{p.payload}</pre></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
