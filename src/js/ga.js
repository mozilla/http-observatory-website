import dntEnabled from "@mozmeao/dnt-helper";

if (!dntEnabled()) {
  var gaScript = document.createElement("script");
  gaScript.async = 1;
  gaScript.src = "https://www.googletagmanager.com/gtag/js?id=G-0YL01S2FDK";
  document.head.appendChild(gaScript);

  window.dataLayer = window.dataLayer || [];
  function gtag() {
    dataLayer.push(arguments);
  }
  gtag("js", new Date());

  gtag("consent", "default", {
    analytics_storage: "denied",
  });

  gtag("config", "G-0YL01S2FDK");
}