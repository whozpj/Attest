import { Link, Navigate, Route, Routes } from "react-router-dom";
import { Layout } from "./components/Layout.js";
import { SignIn } from "./routes/SignIn.js";
import { Enrol } from "./routes/Enrol.js";
import { Requests } from "./routes/Requests.js";
import { Request } from "./routes/Request.js";
import { ApprovalLink } from "./routes/ApprovalLink.js";

function NotFound() {
  return (
    <Layout anonymous>
      <div className="page-narrow">
        <div className="card center">
          <h1 className="h1">Page not found</h1>
          <p className="prose">There is nothing at this address.</p>
          <Link className="btn btn-ghost" to="/requests">
            Go to your requests
          </Link>
        </div>
      </div>
    </Layout>
  );
}

export function App() {
  return (
    <Routes>
      <Route path="/" element={<Navigate to="/requests" replace />} />
      <Route path="/signin" element={<SignIn />} />
      <Route path="/enrol" element={<Enrol />} />
      <Route path="/requests" element={<Requests />} />
      <Route path="/requests/:id" element={<Request />} />
      <Route path="/a/:token" element={<ApprovalLink />} />
      <Route path="*" element={<NotFound />} />
    </Routes>
  );
}
