local http = require "http"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Para cada puerto abierto detectado por Nmap (excepto 80 y 443, demasiado
conocidos como para necesitar documentacion), busca en el sitemap.xml de
HackTricks (https://hacktricks.wiki/en/sitemap.xml) las paginas cuya URL
haga referencia a ese numero de puerto (o al nombre del servicio detectado
por -sV) y las muestra como enlaces en la salida del escaneo. Las paginas
de tecnologias web especificas (wordpress, jboss, tomcat...) se colapsan
en un unico enlace a la metodologia general de pentesting web.

El sitemap se descarga UNA sola vez por ejecucion de nmap (se cachea en
nmap.registry) y se reutiliza para todos los puertos, para no golpear el
servidor de HackTricks en cada puerto.

Uso basico:
  nmap -sV --script hacktricks-links <objetivo>

Args del script:
  hacktricks-links.hyperlink   -- si es "true", envuelve los enlaces con
                                   secuencias OSC-8 para que sean
                                   clicables directamente en terminales
                                   compatibles (iTerm2, kitty, gnome-terminal,
                                   Windows Terminal, wezterm, etc). Por
                                   defecto viene desactivado porque la
                                   mayoria de terminales ya autolinkan URLs
                                   en texto plano, y el escape OSC-8 puede
                                   ensuciar la salida -oN/-oG.
  hacktricks-links.max          -- numero maximo de enlaces a mostrar por
                                   puerto (por defecto 5).
]]

---
-- @usage
-- nmap -sV --script hacktricks-links <objetivo>
--
-- @args hacktricks-links.hyperlink activa hipervinculos OSC-8 clicables
-- @args hacktricks-links.max maximo de enlaces por puerto (defecto 5)
--
-- @output
-- PORT   STATE SERVICE
-- 21/tcp open  ftp
-- | hacktricks-links:
-- |   https://hacktricks.wiki/en/network-services-pentesting/pentesting-21-ftp/index.html
-- |_  https://hacktricks.wiki/en/network-services-pentesting/pentesting-ftp/ftp-bounce-attack.html

author = "Generado con Claude"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "external"}

local SITEMAP_URL = "https://hacktricks.wiki/en/sitemap.xml"

portrule = function(host, port)
  -- Los puertos 80 y 443 son tan conocidos (HTTP/HTTPS) que no aportan
  -- valor mostrarles documentacion de HackTricks: cualquiera que este
  -- pivoteando ya sabe que son web. Los excluimos explicitamente.
  if port.number == 80 or port.number == 443 then
    return false
  end
  return port.state == "open"
end

-- Descarga y cachea el sitemap (una vez por ejecucion de nmap, sin importar
-- cuantos puertos abiertos haya).
-- Devuelve una tabla de URLs (o tabla vacia si algo falla).
--
-- NOTA: usamos http.get_url() en lugar de http.get() porque get_url()
-- parsea el esquema (https://) directamente de la URL y gestiona el TLS
-- el mismo, sin depender de una clave "ssl" en la tabla de opciones,
-- cuyo soporte varia entre versiones de la libreria http.lua de NSE.
--
-- IMPORTANTE - concurrencia: Nmap ejecuta los scripts NSE de varios
-- puertos EN PARALELO (como corutinas). Sin proteccion, dos puertos
-- abiertos podrian ver la cache vacia al mismo tiempo y disparar dos
-- descargas simultaneas del sitemap (~3MB cada una), lo cual ademas
-- choca con el limite de cache HTTP interno de NSE (1MB por defecto,
-- script-arg http.max-cache-size) y puede hacer que una de las dos
-- llamadas reciba una respuesta sin body. Por eso usamos un nmap.mutex:
-- solo el primer hilo que llega hace la peticion de red; el resto
-- espera en el mutex y luego reutiliza el resultado ya cacheado.
local function get_sitemap_urls()
  local cached = nmap.registry.hacktricks_sitemap_urls
  if cached ~= nil then
    return cached
  end

  local mutex = nmap.mutex("hacktricks-links-sitemap-fetch")
  mutex("lock")

  -- Volver a comprobar tras adquirir el lock: es posible que otro hilo
  -- ya haya descargado y poblado la cache mientras esperabamos.
  cached = nmap.registry.hacktricks_sitemap_urls
  if cached ~= nil then
    mutex("done")
    return cached
  end

  local urls = {}
  local ok, resp = pcall(http.get_url, SITEMAP_URL, {
    timeout = 20000,
    redirect_ok = true,
    any_af = true,
    -- El sitemap de HackTricks pesa varios MB (crece con el tiempo). El
    -- limite por defecto de la libreria http.lua de NSE es de solo 2MB
    -- (MAX_BODY_SIZE), asi que sin esto la respuesta se rechaza con
    -- "response body too large" aunque el servidor responda 200 OK.
    max_body_size = 10 * 1024 * 1024,
    -- La cache HTTP interna de NSE tiene un limite de 1MB por defecto
    -- (http.max-cache-size), muy por debajo del tamano real del
    -- sitemap. Como ya hacemos nuestra propia cache en nmap.registry
    -- (protegida por el mutex de arriba), no necesitamos ni queremos
    -- que esta peticion puntual pase por esa cache interna.
    bypass_cache = true,
    no_cache = true,
    -- Algunos CDN/WAF (Cloudflare, CloudFront, etc.) bloquean el
    -- User-Agent por defecto de NSE porque se identifica a si mismo como
    -- "Nmap Scripting Engine". Lo sustituimos por uno de navegador normal.
    header = {
      ["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        .. "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
      ["Accept"] = "text/xml,application/xml,*/*",
    },
  })

  if not ok then
    stdnse.debug1("Excepcion Lua al pedir el sitemap de HackTricks: %s", tostring(resp))
  elseif not resp then
    stdnse.debug1("http.get_url devolvio nil para %s", SITEMAP_URL)
  elseif resp.status ~= 200 then
    -- IMPORTANTE: cuando la conexion de socket falla del todo (timeout,
    -- conexion rechazada, DNS, TLS, etc.) resp.status y resp.body quedan
    -- en nil, pero resp["status-line"] trae la razon real del fallo
    -- (p.ej. "Error creating socket."). Por eso lo logueamos siempre.
    stdnse.debug1(
      "El sitemap de HackTricks NO se pudo obtener. status=%s status-line=%s body=%s",
      tostring(resp.status),
      tostring(resp["status-line"]),
      tostring(resp.body and resp.body:sub(1, 200)))
  elseif not resp.body or #resp.body == 0 then
    stdnse.debug1("El sitemap de HackTricks respondio 200 pero sin body")
  else
    stdnse.debug1("Sitemap de HackTricks descargado OK, %d bytes", #resp.body)
    -- El sitemap es un <urlset> con entradas <url><loc>...</loc></url>
    for loc in resp.body:gmatch("<loc>%s*(.-)%s*</loc>") do
      table.insert(urls, loc)
    end
    stdnse.debug1("%d URLs extraidas del sitemap", #urls)
  end

  -- Cachear incluso si esta vacia, para no reintentar en cada puerto.
  nmap.registry.hacktricks_sitemap_urls = urls
  mutex("done")
  return urls
end

-- Escapa caracteres magicos de Lua patterns en un string plano.
local function escape_pattern(s)
  return (s:gsub("([%(%)%.%%%+%-%*%?%[%]%^%$])", "%%%1"))
end

-- Devuelve solo la ruta de una URL (sin "https://hacktricks.wiki"), en
-- minusculas. Es CRITICO no matchear contra la URL completa: todas las
-- URLs del sitemap empiezan literalmente por "https://...", asi que
-- buscar el substring "http" o "https" (nombres de servicio por defecto
-- de Nmap para los puertos 80 y 443) contra la URL completa matchearia
-- practicamente CUALQUIER pagina del sitio, no solo las relevantes.
local function url_path(url)
  return (url:match("^https?://[^/]+(/.*)$") or url):lower()
end

-- Busca en las URLs del sitemap las que probablemente documenten el
-- puerto/servicio dado. HackTricks nombra muchas paginas de
-- "network-services-pentesting" incluyendo el numero de puerto en el
-- slug, p.ej. ".../pentesting-21-ftp/..." o ".../4222-pentesting-nats.md".
-- Otras paginas (pentesting-web, pentesting-ssh, pentesting-smtp...) no
-- llevan ningun numero en el nombre, de ahi el refuerzo por servicio.
--
-- Nombres de servicio demasiado genericos quedan excluidos del refuerzo
-- por nombre: aunque ya no puedan matchear por el bug de "https://",
-- siguen siendo demasiado ambiguos para dar resultados utiles.
local GENERIC_SERVICE_NAMES = {
  ["tcpwrapped"] = true,
  ["unknown"] = true,
  ["domain"] = true,
}

-- Varias paginas muy comunes de HackTricks NO llevan el numero de
-- puerto en el slug (p.ej. "pentesting-web", "pentesting-ssh",
-- "pentesting-smtp"), asi que ni el matching por numero ni el matching
-- por nombre de servicio (con "http"/"https", que son demasiado
-- genericos y quedan fuera del refuerzo por nombre) los detectarian.
-- Para los puertos mas habituales, añadimos pistas fijas de que
-- palabra clave buscar en el slug.
local STATIC_PORT_HINTS = {
  [21]   = {"ftp"},
  [22]   = {"ssh"},
  [23]   = {"telnet"},
  [25]   = {"smtp"},
  [53]   = {"dns"},
  [80]   = {"pentesting%-web"},
  [110]  = {"pop"},
  [111]  = {"rpcbind", "portmapper"},
  [135]  = {"msrpc"},
  [139]  = {"smb", "netbios"},
  [143]  = {"imap"},
  [389]  = {"ldap"},
  [443]  = {"pentesting%-web"},
  [445]  = {"smb"},
  [993]  = {"imap"},
  [995]  = {"pop"},
  [1433] = {"mssql"},
  [3306] = {"mysql"},
  [3389] = {"rdp"},
  [5432] = {"postgresql"},
  [5900] = {"vnc"},
  [5985] = {"winrm"},
  [5986] = {"winrm"},
  [8080] = {"pentesting%-web"},
  [8443] = {"pentesting%-web"},
}

local function find_links(urls, port_number, service_name)
  local matches = {}
  local seen = {}
  local port_str = tostring(port_number)

  local port_patterns = {
    "%-" .. port_str .. "%-",  -- -21-
    "%-" .. port_str .. "/",   -- -21/
    "%-" .. port_str .. "$",   -- -21 (fin de linea, antes de la extension)
    "^" .. port_str .. "%-",   -- 4222-pentesting-nats.md (numero al inicio del slug)
  }

  for _, url in ipairs(urls) do
    local path = url_path(url)
    -- nos quedamos solo con el ultimo segmento (el nombre del archivo/carpeta)
    -- para evitar falsos positivos con numeros que aparezcan en otra parte
    -- de la ruta.
    local slug = path:match("([^/]+)/?$") or path
    for _, pat in ipairs(port_patterns) do
      if slug:find(pat) and path:find("network%-services%-pentesting")
        and not seen[url] then
        table.insert(matches, url)
        seen[url] = true
        break
      end
    end
  end

  -- Pistas fijas para puertos comunes cuyo slug no lleva el numero
  -- (ver STATIC_PORT_HINTS mas arriba).
  local hints = STATIC_PORT_HINTS[port_number]
  if hints then
    for _, hint in ipairs(hints) do
      for _, url in ipairs(urls) do
        local path = url_path(url)
        if not seen[url]
          and path:find("network%-services%-pentesting")
          and path:find(hint) then
          table.insert(matches, url)
          seen[url] = true
        end
      end
    end
  end

  -- Refuerzo: si nmap identifico el nombre del servicio (ej. "ftp",
  -- "smb", "rdp"), tambien buscamos ese nombre como PALABRA COMPLETA
  -- (no como substring suelto) dentro del slug de paginas de pentesting
  -- de red, para pillar paginas que no llevan el numero de puerto.
  if service_name and service_name ~= "" and service_name ~= "unknown"
    and not GENERIC_SERVICE_NAMES[service_name:lower()] then
    local svc = service_name:lower()
    if #svc >= 3 then
      local svc_pat = escape_pattern(svc)
      -- %f[%a] / %f[%A] son "frontier patterns": exigen que svc este
      -- rodeado de limites de palabra (no sea parte de una palabra mas
      -- larga), para que "ftp" no matchee "sftp" ni "tftp" por accidente.
      local boundary_pat = "%f[%a]" .. svc_pat .. "%f[%A]"
      for _, url in ipairs(urls) do
        local path = url_path(url)
        if not seen[url]
          and path:find("network%-services%-pentesting")
          and path:find(boundary_pat) then
          table.insert(matches, url)
          seen[url] = true
        end
      end
    end
  end

  return matches
end

-- Cuando un puerto (que no sea 80/443, ya excluidos) resulta ser web
-- (8080, 8443, un WAF raro, etc.), el matching por servicio/hints puede
-- devolver muchas paginas de tecnologias especificas bajo pentesting-web/
-- (wordpress, jboss, tomcat...). En vez de listarlas todas, las
-- colapsamos en un unico enlace a la metodologia general de pentesting
-- web.
local WEB_PATH_MARKER = "network-services-pentesting/pentesting-web/"
local WEB_METHOD_URL = "https://hacktricks.wiki/en/network-services-pentesting/pentesting-web/index.html"
local WEB_METHOD_LABEL = "80,443 - Pentesting Web Methodology - HackTricks"

action = function(host, port)
  local urls = get_sitemap_urls()
  if #urls == 0 then
    return nil
  end

  local matches = find_links(urls, port.number, port.service)
  if #matches == 0 then
    return nil
  end

  local entries = {}
  local has_web_page = false
  for _, url in ipairs(matches) do
    if url:find(WEB_PATH_MARKER, 1, true) then
      has_web_page = true
    else
      table.insert(entries, { url = url })
    end
  end
  if has_web_page then
    table.insert(entries, { url = WEB_METHOD_URL, label = WEB_METHOD_LABEL })
  end

  if #entries == 0 then
    return nil
  end

  local max = tonumber(stdnse.get_script_args("hacktricks-links.max")) or 5
  local use_hyperlink = stdnse.get_script_args("hacktricks-links.hyperlink") == "true"

  local out = {}
  for i, entry in ipairs(entries) do
    if i > max then break end
    if use_hyperlink then
      -- Secuencia OSC-8: \27]8;;URL\27\TEXTO\27]8;;\27\
      local text = entry.label or entry.url
      table.insert(out, string.format("\27]8;;%s\27\\%s\27]8;;\27\\", entry.url, text))
    elseif entry.label then
      table.insert(out, entry.label .. ": " .. entry.url)
    else
      table.insert(out, entry.url)
    end
  end

  return stdnse.format_output(true, out)
end
