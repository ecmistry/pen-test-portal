import { Toaster } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import NotFound from "@/pages/NotFound";
import { Route, Switch } from "wouter";
import ErrorBoundary from "./components/ErrorBoundary";
import { ThemeProvider } from "./contexts/ThemeContext";
import Home from "./pages/Home";
import Dashboard from "./pages/Dashboard";
import Targets from "./pages/Targets";
import ScanDetail from "./pages/ScanDetail";
import Scans from "./pages/Scans";
import Reports from "./pages/Reports";
import ReportView from "./pages/ReportView";
import Schedules from "./pages/Schedules";
import AdminPanel from "./pages/AdminPanel";
import Methodology from "./pages/Methodology";

function Router() {
  return (
    <Switch>
      <Route path="/" component={Home} />
      <Route path="/dashboard" component={Dashboard} />
      <Route path="/targets" component={Targets} />
      <Route path="/scans" component={Scans} />
      <Route path="/scans/:id" component={ScanDetail} />
      <Route path="/reports" component={Reports} />
      <Route path="/reports/:scanId" component={ReportView} />
      <Route path="/schedules" component={Schedules} />
      <Route path="/methodology" component={Methodology} />
      <Route path="/admin" component={AdminPanel} />
      <Route path="/404" component={NotFound} />
      <Route component={NotFound} />
    </Switch>
  );
}

function App() {
  return (
    <ErrorBoundary>
      <ThemeProvider defaultTheme="dark">
        <TooltipProvider>
          <Toaster theme="dark" />
          <Router />
        </TooltipProvider>
      </ThemeProvider>
    </ErrorBoundary>
  );
}

export default App;
