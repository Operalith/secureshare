window.addEventListener("load", () => {
  const target = document.getElementById("swagger-ui");
  if (!target || typeof SwaggerUIBundle === "undefined") return;
  SwaggerUIBundle({
    url: target.dataset.openapiUrl || "/openapi.yaml",
    dom_id: "#swagger-ui",
    deepLinking: true,
    displayRequestDuration: true,
    persistAuthorization: false,
    tryItOutEnabled: false,
    validatorUrl: null,
    presets: [
      SwaggerUIBundle.presets.apis,
      SwaggerUIStandalonePreset,
    ],
    layout: "StandaloneLayout",
  });
});
