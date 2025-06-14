<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>VirSign API Documentation</title>

  <!-- Gunakan HTTPS agar tidak kena mixed content -->
  <link rel="icon" type="image/png" href="https://bettd-production.up.railway.app/docs/asset/favicon-32x32.png">

  <!-- Swagger UI CSS CDN -->
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@4.18.3/swagger-ui.css">
  
  <!-- HARDCODE CDN agar SwaggerUIBundle tidak error -->
  <script src="https://unpkg.com/swagger-ui-dist@4.18.3/swagger-ui-bundle.js"></script>
  <script src="https://unpkg.com/swagger-ui-dist@4.18.3/swagger-ui-standalone-preset.js"></script>

  <style>
    html {
      box-sizing: border-box;
      overflow: -moz-scrollbars-vertical;
      overflow-y: scroll;
    }
    *, *:before, *:after {
      box-sizing: inherit;
    }
    body {
      margin: 0;
      background: #fafafa;
    }
  </style>
</head>

<body>
  <div id="swagger-ui"></div>

  <script>
    window.onload = function() {
      const ui = SwaggerUIBundle({
        url: "{{ route('l5-swagger.default.docs') }}",
        dom_id: '#swagger-ui',
        deepLinking: true,
        presets: [
          SwaggerUIBundle.presets.apis,
          SwaggerUIStandalonePreset
        ],
        layout: "StandaloneLayout"
      });
      window.ui = ui;
    }
  </script>
</body>
</html>
