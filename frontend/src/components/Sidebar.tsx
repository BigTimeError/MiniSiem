import { NavLink } from "react-router-dom";

function Sidebar() {
  const getNavLinkClass = ({ isActive }: { isActive: boolean }) =>
    isActive ? "nav-link active" : "nav-link";

  return (
    <aside className="sidebar">
      <div className="sidebar-logo">
        MiniSIEM
      </div>

      <nav className="sidebar-nav">
        <NavLink to="/dashboard" className={getNavLinkClass}>
          Dashboard
        </NavLink>

        <NavLink to="/events" className={getNavLinkClass}>
          Events
        </NavLink>

        <NavLink to="/alerts" className={getNavLinkClass}>
          Alerts
        </NavLink>

        <NavLink to="/hosts" className={getNavLinkClass}>
          Hosts
        </NavLink>

        <NavLink to="/correlations" className={getNavLinkClass}>
          Correlations
        </NavLink>

        <NavLink to="/incidents" className={getNavLinkClass}>
          Incidents
        </NavLink>
      </nav>
    </aside>
  );
}

export default Sidebar;