<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>VirSign API Documentation</title>
  <link rel="icon" type="image/png" href="https://bettd-production.up.railway.app/docs/asset/favicon-32x32.png">

  <!-- Tailwind CSS with your exact gradient configuration -->
  <script src="https://cdn.tailwindcss.com"></script>
  <script>
    tailwind.config = {
      theme: {
        extend: {
          colors: {
            primary: '#692e66',
            secondary: '#b66864',
            accent: '#d4b2d8',
          },
          backgroundImage: {
            'virsign-gradient': 'linear-gradient(135deg, rgba(105, 46, 102, 0.9) 0%, rgba(182, 104, 100, 1) 100%)',
          }
        }
      }
    }
  </script>

  <!-- Swagger UI CSS -->
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@4.18.3/swagger-ui.css">
  
  <!-- Swagger JS -->
  <script src="https://unpkg.com/swagger-ui-dist@4.18.3/swagger-ui-bundle.js"></script>
  <script src="https://unpkg.com/swagger-ui-dist@4.18.3/swagger-ui-standalone-preset.js"></script>

  <style>
    /* Custom Swagger overrides using your gradient */
    .swagger-ui .topbar {
      background-image: linear-gradient(135deg, rgba(105, 46, 102, 0.9) 0%, rgba(182, 104, 100, 1) 100%);
      @apply text-white p-4 shadow-xl;
    }
    
    .swagger-ui .info .title {
      @apply text-primary text-3xl font-bold mb-3;
    }
    
    .swagger-ui .info .base-url {
      @apply text-secondary font-medium;
    }
    
    .swagger-ui .btn {
      background-image: linear-gradient(135deg, rgba(105, 46, 102, 0.9) 0%, rgba(182, 104, 100, 1) 100%);
      @apply text-white font-medium py-2 px-4 rounded-md shadow-md transition-all hover:shadow-lg hover:brightness-110;
    }
    
    .swagger-ui .opblock .opblock-summary {
      @apply border border-gray-200 rounded-lg transition-all hover:bg-gray-50 hover:shadow-sm;
    }
    
    .swagger-ui .opblock .opblock-summary-path {
      @apply font-semibold text-gray-800;
    }
    
    .swagger-ui .model-box {
      @apply bg-gray-50 rounded-lg shadow-inner p-4;
    }
    
    /* Floating action button with your gradient */
    .fab {
      background-image: linear-gradient(135deg, rgba(105, 46, 102, 0.9) 0%, rgba(182, 104, 100, 1) 100%);
      @apply fixed bottom-8 right-8 w-14 h-14 rounded-full text-white flex items-center justify-center shadow-xl cursor-pointer transition-all hover:scale-105 hover:shadow-2xl z-50;
    }
    
    /* API method tags */
    .swagger-ui .opblock.opblock-get .opblock-summary-method {
      @apply bg-green-500 text-white;
    }
    
    .swagger-ui .opblock.opblock-post .opblock-summary-method {
      @apply bg-blue-500 text-white;
    }
    
    .swagger-ui .opblock.opblock-put .opblock-summary-method {
      @apply bg-yellow-500 text-white;
    }
    
    .swagger-ui .opblock.opblock-delete .opblock-summary-method {
      @apply bg-red-500 text-white;
    }
  </style>
</head>

<body class="bg-gray-50 font-sans">
  <!-- Gradient Header -->
  <header class="bg-gradient-to-r from-[#692e66]/90 to-[#b66864] text-white py-10 text-center mb-8 shadow-md">
    <div class="container mx-auto px-4">
      <div class="flex justify-center items-center mb-4">
        <img src="https://bettd-production.up.railway.app/docs/asset/favicon-32x32.png" alt="Logo" class="h-10 mr-3">
        <h1 class="text-4xl font-bold">VirSign API</h1>
      </div>
      <p class="text-lg opacity-90 max-w-3xl mx-auto">
        Interactive API documentation with your branded gradient theme
      </p>
    </div>
  </header>

  <!-- Main Content -->
  <main class="container mx-auto px-4 pb-20">
    <div id="swagger-ui" class="shadow-lg rounded-lg overflow-hidden"></div>
  </main>

  <!-- Back to Top Button -->
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
        docExpansion: 'list',
        defaultModelsExpandDepth: 1,
        defaultModelExpandDepth: 1,
        displayRequestDuration: true,
        tryItOutEnabled: true,
        syntaxHighlight: {
          activate: true,
          theme: "arta"
        },
        onComplete: function() {
          // Add custom logo to topbar
          const topbar = document.querySelector('.topbar');
          if (topbar) {
            const logoWrapper = document.createElement('div');
            logoWrapper.className = 'flex items-center ml-5 gap-2';
            
            const logo = document.createElement('img');
            logo.src = 'https://bettd-production.up.railway.app/docs/asset/favicon-32x32.png';
            logo.className = 'h-8';
            
            const title = document.createElement('span');
            title.className = 'text-white font-semibold text-xl';
            title.textContent = 'VirSign API';
            
            logoWrapper.appendChild(logo);
            logoWrapper.appendChild(title);
            topbar.insertBefore(logoWrapper, topbar.firstChild);
          }
          
          // Add subtle animation to operation blocks
          const opblocks = document.querySelectorAll('.opblock');
          opblocks.forEach(opblock => {
            opblock.className += ' transition-transform duration-200 hover:scale-[1.002]';
          });
        }
      });
      
      window.ui = ui;
    };
  </script>
</body>
</html>