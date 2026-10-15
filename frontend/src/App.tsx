import {
BrowserRouter,
Navigate,
Route,
Routes,
} from "react-router-dom";

import Dashboard from "./pages/Dashboard";
import Events from "./pages/Events";
import EventDetail from "./pages/EventDetail";
import Alerts from "./pages/Alerts";
import AlertDetail from "./pages/AlertDetail";
import Hosts from "./pages/Hosts";
import HostDetail from "./pages/HostDetail";
import Correlations from "./pages/Correlations";
import CorrelationDetail from "./pages/CorrelationDetail";
import Incidents from "./pages/Incidents";
import IncidentDetail from "./pages/IncidentDetail";

function App() {
return ( <BrowserRouter> <Routes>
<Route
path="/"
element={<Navigate to="/dashboard" replace />}
/>

    <Route
      path="/dashboard"
      element={<Dashboard />}
    />

    <Route
      path="/events"
      element={<Events />}
    />

    <Route
      path="/events/:eventId"
      element={<EventDetail />}
    />

    <Route
      path="/alerts"
      element={<Alerts />}
    />

    <Route
      path="/alerts/:alertId"
      element={<AlertDetail />}
    />

    <Route
      path="/hosts"
      element={<Hosts />}
    />

    <Route
      path="/hosts/:hostId"
      element={<HostDetail />}
    />

    <Route 
      path="/correlations" 
      element={<Correlations />} 
    />
    
    <Route
      path="/correlations/:correlationId"
      element={<CorrelationDetail />}
    />

    <Route
      path="/incidents"
      element={<Incidents />}
    />

    <Route
      path="/incidents/:incidentId"
      element={<IncidentDetail />}
    />
  </Routes>
</BrowserRouter>


);
}

export default App;
