import React from "react";
import { useAuth } from "./AuthContext";
import { Link } from "react-router-dom";

export default function HomePage() {
  const { auth } = useAuth();

  if (!auth) {
    return (
      <div>
        <h1>Home</h1>
        <p>You are not logged in.</p>
        <Link to="/login">Go to login</Link>
      </div>
    );
  }


return (
  <div>
    <h1>Home</h1>
    <p>You are logged in.</p>

    <h3>Claims</h3>
    <pre>{JSON.stringify(auth.claims, null, 2)}</pre>
  </div>
);

}
