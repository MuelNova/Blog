import React from "react";
import { Redirect } from "@docusaurus/router";

// Just an alias for /blog/tags/otaku-houmen
export default function Posts(): JSX.Element {
  return <Redirect to="blog/tags/otaku-houmen" />;
}
