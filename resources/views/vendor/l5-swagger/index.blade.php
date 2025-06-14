<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>VirSign API Documentation</title>
  <link rel="icon" type="image/png" href="https://bettd-production.up.railway.app/docs/asset/favicon-32x32.png">

  <!-- Tailwind CSS CDN -->
  <script src="https://cdn.tailwindcss.com"></script>
  
  <!-- Custom Tailwind Configuration untuk Theme Gradient [#692e66]/90 to [#b66864] -->
  <script>
    tailwind.config = {
      theme: {
        extend: {
          colors: {
            primary: '#692e66',
            secondary: '#b66864',
            highlight: '#d4b2d8',
          },
          backgroundImage: {
            'gradient-primary': 'linear-gradient(135deg, rgba(105, 46, 102, 0.9) 0%, rgba(182, 104, 100, 1) 100%)',
          }
        }
      }
    }
  </script>

  <!-- Swagger UI CSS CDN -->
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@4.18.3/swagger-ui.css">
  
  <!-- Swagger JS CDN -->
  <script src="https://unpkg.com/swagger-ui-dist@4.18.3/swagger-ui-bundle.js"></script>
  <script src="https://unpkg.com/swagger-ui-dist@4.18.3/swagger-ui-standalone-preset.js"></script>

  <style>
    /* Custom Swagger Overrides dengan Tailwind-inspired Styling */
    .swagger-ui .topbar {
      @apply bg-gradient-primary text-white p-4 shadow-lg;
    }
    
    .swagger-ui .info .title {
      @apply text-primary text-3xl font-bold mb-2;
    }
    
    .swagger-ui .info h2 {
      @apply text-secondary text-xl;
    }
    
    .swagger-ui .btn {
      @apply bg-gradient-primary text-white border-none transition-all hover:-translate-y-0.5 hover:shadow-md;
    }
    
    .swagger-ui .opblock .opblock-summary {
      @apply border-gray-200 transition-all hover:bg-gray-50 hover:shadow-sm;
    }
    
    .swagger-ui .model-box {
      @apply bg-gray-50 rounded-lg shadow-sm;
    }
    
    /* Floating Action Button (Tailwind Style) */
    .fab {
      @apply fixed bottom-8 right-8 w-14 h-14 rounded-full bg-gradient-primary text-white flex items-center justify-center shadow-lg cursor-pointer transition-all hover:-translate-y-1 hover:shadow-xl;
    }
  </style>
</head>

<body class="bg-gray-50">
  <!-- Custom Header dengan Tailwind -->
  <header class="bg-gradient-primary text-white py-8 text-center mb-8">
    <div class="container mx-auto px-4">
      <h1 class="text-4xl font-bold mb-2">VirSign API Documentation</h1>
      <p class="text-lg opacity-90 max-w-3xl mx-auto">
        Comprehensive API reference for VirSign services with interactive examples and detailed descriptions.
      </p>
    </div>
  </header>

  <!-- Swagger Container -->
  <div class="container mx-auto px-4">
    <div id="swagger-ui"></div>
  </div>

  <!-- Floating Action Button (Back to Top) -->
  <div class="fab" onclick="window.scrollTo({top: 0, behavior: 'smooth'})">
    <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <path d="M18 15l-6-6-6 6"/>
    </svg>
  </div>

  <script>
    window.onload = function() {
      const ui = SwaggerUIBundle({
        url: "https://bettd-production.up.railway.app/docs",
        dom_id: '#swagger-ui',
        deepLinking: true,
        presets: [
          SwaggerUIBundle.presets.apis,
          SwaggerUIStandalonePreset
        ],
        layout: "StandaloneLayout",
        filter: true,
        tryItOutEnabled: true,
        onComplete: function() {
          // Tambahkan logo custom ke topbar
          const topbar = document.querySelector('.topbar');
          if (topbar) {
            const logoWrapper = document.createElement('div');
            logoWrapper.className = 'flex items-center ml-5';
            
            const logo = document.createElement('img');
            logo.src = 'https://bettd-production.up.railway.app/docs/asset/favicon-32x32.png';
            logo.className = 'h-8 mr-3';
            
            const title = document.createElement('span');
            title.className = 'text-white font-semibold text-xl';
            title.textContent = 'VirSign API';
            
            logoWrapper.appendChild(logo);
            logoWrapper.appendChild(title);
            topbar.insertBefore(logoWrapper, topbar.firstChild);
          }
        }
      });
      
      window.ui = ui;
    };
  </script>
</body>
</html>