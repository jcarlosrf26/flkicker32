// FLKicker 0.7 - Cliente de Kick estilo FreeTube para FLinux-JC / FLinux-JC64
// C++ + FLTK 1.3. Via anonima (sin cuenta ni claves): usa los mismos
// endpoints publicos que la web de kick.com usa para visitantes.
//
// ---- 0.7 ----
// - Todos los textos de la app alineados a la izquierda.
// - La busqueda de canales en la lista va en orden alfabetico.
// - Al reproducir, la app se bloquea (solo Detener e Info activos)
//   hasta que mplayer se cierra.
// - La busqueda muestra tambien canales apagados, con punto rojo en
//   vez de verde; se pueden marcar como favoritos y al prender salen
//   en Favoritos con el punto verde.
// - Efecto de carga: circulo verde girando alrededor del icono K de
//   la esquina mientras arranca el video.
//
//   Directos:  GET https://api.kick.com/private/v1/livestreams (paginado)
//   Canal:     GET https://kick.com/api/v2/channels/{slug}
//              -> livestream + playback_url CON token (el del listado
//                 private/v1 viene sin token y el CDN lo rechaza).
//   Sugerencias: GET https://search.kick.com/collections/channel/
//              documents/search?q=...&filter_by=is_live:=true
//              (el indice Typesense de la propia web de Kick, con su
//                 clave publica de solo-busqueda embebida en el JS que la
//                 web reparte a cada visitante; se filtra a canales EN
//                 VIVO y sin banear, ordenados por seguidores).
//              Las sugerencias son candidatas: el veredicto de "en
//                 directo" lo sigue dando api/v2 al dar Enter/REPRODUCIR.
//
// Reproduccion: master m3u8 -> variante por altura (160/240/360/480,
// defecto 360; si no hay altura exacta, la inmediata inferior; si
// tampoco, la mas baja: con 160p se admite el 160 exacto o el mas bajo
// disponible) -> ffmpeg demuxa el HLS y entrega MPEG-TS por tuberia a
// mplayer
// (misma idea que el feed de FLTV). El mplayer de Tiny Core no puede con
// HLS solo: con la URL pelada, libavformat recibe de la cache de mplayer
// la URL ficticia "mp:<url>" y no puede abrir ningun segmento (mplayer
// muere al instante: es el fallo que reporto Juanca en la Dell); con el
// esquema ffmpeg://, el demuxer de mplayer exige buscar hacia atras en
// un flujo lineal ("Cannot seek backward in linear streams!") y tambien
// muere. ffmpeg 7 (ffmpeg7.tcz) si demuxa HLS/HTTPS de forma nativa.
// A mplayer hay que darle el demuxer lavf con el formato forzado
// (-demuxer lavf -lavfdopts format=mpegts): sin forzar, su sondeo sobre
// la tuberia busca hacia atras y muere igual (en 32 bits se vio ese
// mismo "Cannot seek backward in linear streams!").
// Nota de dependencias: ffmpeg7.tcz del repo no declara libplacebo.tcz
// y su ffmpeg lo enlaza; por eso el .dep de FLKicker lo pide expreso.
//
// Refuerzo de red (sobre la 0.2): timeouts largos (conex. 15 s, total 60 s),
// 2 reintentos con 2 s de pausa en errores transitorios, solo IPv4
// (CURLOPT_IPRESOLVE_V4) y NOSIGNAL (obligado con hilos). Si el fetch
// del master HLS sigue cayendo tras los reintentos, no se muere: se le
// entrega la URL master tal cual a ffmpeg y que el resuelva el HLS
// (estado «Reproduciendo via master»). Los errores nombran el host que
// fallo y el codigo curl exacto, para diagnosticar con una foto.
// En la Dell de la 0.2 la lista cargaba y el curl manual respondia
// 200 en 0,94 s, pero el fetch del master (CDN de Kick) expiraba
// (curl 28): de ahi los reintentos y el fallback.
//
// Tema claro/oscuro con oscuro por defecto; preferencia y calidad se
// guardan en ~/.flkickerrc.
//
// Buscador con sugerencias: al teclear, la tabla se filtra al momento en
// local sobre los directos cargados (empiezan por el texto, luego lo
// contienen; orden por espectadores dentro de cada grupo) y, tras ~0,5 s
// sin teclear (debounce en watch_cb), se piden sugerencias EN VIVO a la
// plataforma (Typesense de la web) que se anaden tras los locales, sin
// duplicar y solo si siguen en vivo. El indice de la plataforma no trae
// espectadores, asi que van ordenados por seguidores. Solo local: en
// «Favoritos» las sugerencias tambien pasan por el filtro de likes.
// Bug del Enter corregido en la 0.5: antes se fiaba de event_key() en
// el callback de texto y el Enter se lo tragaba (el usuario se quedaba
// en «Filtro local: 0 de N»); ahora un SearchInput caza FL_KEYDOWN.
//
// Logo: el icono K (flkicker-48.png del paquete) en la esquina superior
// izquierda de la ventana, igual en modo oscuro y claro. Boton «i» en
// la esquina superior derecha: abre la ayuda (estilo FLTube), que se
// pinta con el tema actual de la app (oscuro o claro).

#include <FL/Fl.H>
#include <FL/Fl_Window.H>
#include <FL/Fl_Box.H>
#include <FL/Fl_Image.H>
#include <FL/Fl_PNG_Image.H>
#include <FL/Fl_Button.H>
#include <FL/Fl_Input.H>
#include <FL/Fl_Table_Row.H>
#include <FL/Fl_Browser.H>
#include <FL/Fl_Text_Display.H>
#include <FL/Fl_Text_Buffer.H>
#include <FL/fl_draw.H>
#include <curl/curl.h>
#include <json-c/json.h>

// Declaraciones minimas de libcrypto para verificar la firma Ed25519 de
// endpoints.json. Se declaran a mano (sin <openssl/evp.h>) porque el
// sysroot de compilacion i386 no trae los headers de OpenSSL; el ABI de
// estas funciones es estable entre OpenSSL 1.1.1 y 3.x.
extern "C" {
typedef struct evp_pkey_st EVP_PKEY;
typedef struct evp_md_ctx_st EVP_MD_CTX;
enum { EVP_PKEY_ED25519 = 1087 };
EVP_PKEY *EVP_PKEY_new_raw_public_key(int type, void *e,
                                      const unsigned char *key,
                                      size_t keylen);
EVP_MD_CTX *EVP_MD_CTX_new(void);
int EVP_DigestVerifyInit(EVP_MD_CTX *ctx, void **pctx, const void *type,
                         void *e, EVP_PKEY *pkey);
int EVP_DigestVerify(EVP_MD_CTX *ctx, const unsigned char *sig, size_t siglen,
                     const unsigned char *tbs, size_t tbslen);
void EVP_MD_CTX_free(EVP_MD_CTX *ctx);
void EVP_PKEY_free(EVP_PKEY *pkey);
}

#include <pthread.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <algorithm>
#include <set>
#include <string>
#include <vector>

static const char *FLKICK_UA =
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0";
// ---- 0.6: endpoints configurables por config remota firmada ----
// Valores compilados = respaldo. Al abrir la app, se intenta descargar
// endpoints.json (firmado con Ed25519); si la firma es valida, estos
// valores se sustituyen por los remotos. Asi, si Kick rota sus URLs
// internas, basta actualizar el JSON en el repo: la app se adapta al
// reabrirla, sin recompilar ni redistribuir el .tcz.
static const char *EP_CONFIG_URL =
    "https://raw.githubusercontent.com/jcarlosrf26/flkicker32/main/endpoints.json";
// Clave publica Ed25519 (32 bytes) que firma endpoints.json. La privada
// vive solo en el taller, nunca en el repo.
static const unsigned char EP_PUBKEY[32] = {
    0x9a, 0xd9, 0xed, 0x2f, 0xa3, 0x2b, 0x1d, 0xc0,
    0x28, 0xdd, 0x0c, 0x3d, 0x14, 0x65, 0x4a, 0x77,
    0x02, 0xef, 0xdc, 0x5d, 0x90, 0xd5, 0x7b, 0xd1,
    0xfe, 0x3e, 0xd1, 0xdd, 0x59, 0xa9, 0xb0, 0x0e
};

static std::string API_LIST = "https://api.kick.com/private/v1/livestreams";
static std::string API_CHAN = "https://kick.com/api/v2/channels/";
static std::string API_SEARCH =
    "https://search.kick.com/collections/channel/documents/search";
// Clave publica de solo-busqueda que la propia web de Kick incrusta en
// su JS (NEXT_PUBLIC_TYPESENSE_API_KEY): es la que usa el buscador de
// kick.com para cualquier visitante, sin cuenta.
static std::string TS_API_KEY = "nXIMW0iEN6sMujFYjFuhdrSwVow3pDQu";

// ---------------------------------------------------------------- datos
struct Row {
    std::string slug;
    std::string user;
    std::string title;
    long viewers = 0;
    std::string category;
    bool live = true;  // 0.7: false = canal apagado (punto rojo)
};

struct Vod {
    std::string title;
    std::string date;
    std::string source;
    long duration_ms = 0;
    long views = 0;
};
// ---------------------------------------------------------------- estado
static bool g_dark = true;        // oscuro por defecto
static int  g_quality = 360;      // calidad por defecto
static const int QUALITIES[] = {160, 240, 360, 480, 720};

// ---- 0.4: favoritos con like (pulgar) y calidad 720p ----
static std::set<std::string> g_likes;  // slugs de canales con like
static bool g_favs_mode = false;       // true: la lista solo muestra likes

static Fl_Window *g_win = nullptr;
static Fl_Input  *g_input = nullptr;
static Fl_Button *g_btn_search = nullptr;
static Fl_Button *g_btn_info = nullptr;
static Fl_Button *g_btn_list = nullptr;
static Fl_Button *g_btn_favs = nullptr;
static Fl_Button *g_btn_theme = nullptr;
static Fl_Button *g_btn_play = nullptr;
static Fl_Button *g_btn_quality = nullptr;
static Fl_Button *g_btn_stop = nullptr;
static Fl_Button *g_btn_vod = nullptr;
static Fl_Window *g_vod_win = nullptr;
static Fl_Browser *g_vod_browser = nullptr;
static Fl_Box *g_vod_status = nullptr;
static Fl_Button *g_vod_favorite = nullptr;
static std::vector<Vod> g_vods;
static std::string g_vod_channel;
static Fl_Box    *g_lbl_search = nullptr;
static Fl_Box    *g_lbl_head = nullptr;
static Fl_Box    *g_lbl_player = nullptr;
static Fl_Box    *g_status = nullptr;
static Fl_Box    *g_version = nullptr;

static std::vector<Row> g_rows;   // directos cargados (red, en orden de API)
static std::vector<Row> g_view;   // filas visibles tras el filtro local

// ---- 0.5: sugerencias EN VIVO de la plataforma al teclear ----
static std::vector<Row> g_sugg_rows;    // ultimas sugerencias de la plataforma
static std::string g_sugg_for;          // texto (minusculas) al que responden
static std::string g_sugg_inflight;     // texto con un job ya volando
static std::string g_sugg_queued;       // texto esperando al debounce
static double g_last_key_t = 0;         // instante del ultimo tecleo

static pid_t  g_player_pid = -1;
static double g_player_t0 = 0;
static bool   g_user_stopped = false;
static std::string g_playing_label;

// ---- 0.7: efecto de carga en el icono K de la esquina ----
// Circulo verde girando alrededor del logo mientras arranca el video.
struct LogoBox : Fl_Box {
    int spin = -1;  // <0: quieto; >=0: angulo del arco de carga
    LogoBox(int X, int Y, int W, int H) : Fl_Box(X, Y, W, H) {}
    void draw() override {
        Fl_Box::draw();
        if (spin >= 0) {
            int cx = x() + w() / 2, cy = y() + h() / 2, R = 26;
            fl_color(fl_rgb_color(117, 224, 32));
            fl_line_style(FL_SOLID, 4);
            fl_arc(cx - R, cy - R, 2 * R, 2 * R, (double)spin,
                   (double)spin + 270.0);
            fl_line_style(FL_SOLID, 1);
        }
    }
};
static LogoBox *g_logo = nullptr;

static void logo_spin_cb(void *) {
    if (g_logo && g_logo->spin >= 0) {
        g_logo->spin = (g_logo->spin + 15) % 360;
        g_logo->redraw();
        Fl::repeat_timeout(0.06, logo_spin_cb);
    }
}
static void logo_spin_start() {
    if (!g_logo) return;
    Fl::remove_timeout(logo_spin_cb);
    g_logo->spin = 0;
    g_logo->redraw();
    Fl::add_timeout(0.06, logo_spin_cb);
}
static void logo_spin_stop() {
    if (!g_logo) return;
    Fl::remove_timeout(logo_spin_cb);
    g_logo->spin = -1;
    g_logo->redraw();
}

// ---------------------------------------------------------------- config
static std::string rc_path() {
    const char *h = getenv("HOME");
    return std::string(h ? h : "/tmp") + "/.flkickerrc";
}

static std::string trim_line(const char *s) {
    while (*s == ' ' || *s == '\t') s++;
    std::string out = s ? s : "";
    while (!out.empty()) {
        char c = out[out.size() - 1];
        if (c == '\n' || c == '\r' || c == ' ' || c == '\t')
            out.erase(out.size() - 1);
        else break;
    }
    return out;
}

static void cfg_load() {
    FILE *f = fopen(rc_path().c_str(), "r");
    if (!f) return;
    char ln[128];
    while (fgets(ln, sizeof(ln), f)) {
        if (strncmp(ln, "tema=claro", 10) == 0) g_dark = false;
        else if (strncmp(ln, "tema=oscuro", 11) == 0) g_dark = true;
        else if (strncmp(ln, "calidad=", 8) == 0) {
            int q = atoi(ln + 8);
            if (q == 160 || q == 240 || q == 360 || q == 480 || q == 720)
                g_quality = q;
        }
        else if (strncmp(ln, "like=", 5) == 0) {
            std::string s = trim_line(ln + 5);
            if (!s.empty()) g_likes.insert(s);
        }
    }
    fclose(f);
}

static void cfg_save() {
    FILE *f = fopen(rc_path().c_str(), "w");
    if (!f) return;
    fprintf(f, "tema=%s\ncalidad=%d\n", g_dark ? "oscuro" : "claro", g_quality);
    for (std::set<std::string>::const_iterator it = g_likes.begin();
         it != g_likes.end(); ++it)
        fprintf(f, "like=%s\n", it->c_str());
    fclose(f);
}

// ---------------------------------------------------------------- tema
struct Palette {
    Fl_Color win, input_bg, txt, btn, header, row, row_alt, sel, sel_txt;
};
static const Palette PAL_DARK = {
    fl_rgb_color(20, 22, 29),  fl_rgb_color(29, 32, 39),
    fl_rgb_color(230, 230, 230), fl_rgb_color(35, 37, 45),
    fl_rgb_color(38, 40, 47),
    fl_rgb_color(24, 26, 33),  fl_rgb_color(28, 30, 38),
    fl_rgb_color(30, 70, 32),  fl_rgb_color(240, 255, 240)};
static const Palette PAL_LIGHT = {
    fl_rgb_color(240, 240, 240), fl_rgb_color(255, 255, 255),
    fl_rgb_color(25, 25, 25),  fl_rgb_color(224, 224, 224),
    fl_rgb_color(232, 232, 232),
    fl_rgb_color(255, 255, 255), fl_rgb_color(245, 245, 245),
    fl_rgb_color(183, 227, 154), fl_rgb_color(20, 40, 10)};
static const Palette &pal() { return g_dark ? PAL_DARK : PAL_LIGHT; }
static Fl_Color kick_green() { return fl_rgb_color(83, 252, 24); }

// ---------------------------------------------------------------- http
struct HttpRes {
    long code = 0;
    int curl_err = 0;
    int attempts = 1;      // intentos reales que costo la peticion
    std::string url;       // URL pedida (diagnostico en la barra)
    std::string body;
};

static size_t wr_cb(void *ptr, size_t sz, size_t nm, void *ud) {
    ((std::string *)ud)->append((const char *)ptr, sz * nm);
    return sz * nm;
}

static std::string host_of(const std::string &url) {
    size_t p = url.find("://");
    if (p == std::string::npos) return url;
    size_t h = url.find('/', p + 3);
    size_t n = (h == std::string::npos ? url.size() : h) - (p + 3);
    return url.substr(p + 3, n);
}

// Errores de transporte que vale la pena reintentar (DNS que parpadea,
// conexion rechazada, tiempo agotado, corte a mitad): los que mataban
// el REPRODUCIR en la Dell con un curl 28 solitario.
static bool curl_transitorio(CURLcode cc) {
    return cc == CURLE_COULDNT_RESOLVE_HOST || cc == CURLE_COULDNT_CONNECT ||
           cc == CURLE_OPERATION_TIMEDOUT  || cc == CURLE_GOT_NOTHING ||
           cc == CURLE_RECV_ERROR;
}

// GET con red reforzada: timeouts largos (conex. 15 s, total 60 s),
// 2 reintentos con 2 s de pausa, solo IPv4 y NOSIGNAL (imprescindible
// para timeouts con DNS dentro de un hilo). xh_name/xh_val anaden una
// cabecera extra (la clave publica de Typesense en las sugerencias).
static HttpRes http_get(const std::string &url, const char *xh_name = nullptr,
                        const char *xh_val = nullptr) {
    HttpRes r;
    r.url = url;
    for (int intento = 1; intento <= 3; intento++) {
        r.attempts = intento;
        r.code = 0;
        r.curl_err = 0;
        r.body.clear();
        CURL *c = curl_easy_init();
        if (!c) { r.curl_err = -1; return r; }
        curl_easy_setopt(c, CURLOPT_URL, url.c_str());
        curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, wr_cb);
        curl_easy_setopt(c, CURLOPT_WRITEDATA, &r.body);
        curl_easy_setopt(c, CURLOPT_USERAGENT, FLKICK_UA);
        curl_easy_setopt(c, CURLOPT_ACCEPT_ENCODING, "");
        curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT, 15L);
        curl_easy_setopt(c, CURLOPT_TIMEOUT, 60L);
        curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 0L);
        curl_easy_setopt(c, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
        curl_easy_setopt(c, CURLOPT_NOSIGNAL, 1L);
        struct curl_slist *hdr = nullptr;
        hdr = curl_slist_append(hdr, "Accept: application/json");
        hdr = curl_slist_append(hdr, "Accept-Language: es-ES,es;q=0.9");
        if (xh_name && xh_val) {
            std::string xh = std::string(xh_name) + ": " + xh_val;
            hdr = curl_slist_append(hdr, xh.c_str());
        }
        curl_easy_setopt(c, CURLOPT_HTTPHEADER, hdr);
        CURLcode cc = curl_easy_perform(c);
        if (cc == CURLE_OK)
            curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &r.code);
        else
            r.curl_err = (int)cc;
        curl_slist_free_all(hdr);
        curl_easy_cleanup(c);
        if (cc == CURLE_OK || !curl_transitorio(cc) || intento == 3)
            return r;
        sleep(2);  // pausa entre reintentos (corre en el hilo del job)
    }
    return r;
}

// ---- 0.6: carga de endpoints.json remoto y firmado ----
static const char *js_str(json_object *o, const char *k);  // definida mas abajo
static int g_ep_state = 0;  // 0: sin intentar, 1: remota valida, 2: respaldo

static bool b64_dec(const std::string &in, std::vector<unsigned char> &out) {
    static const signed char T[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1 };
    out.clear();
    unsigned acc = 0; int bits = 0;
    for (size_t i = 0; i < in.size(); i++) {
        unsigned char ch = (unsigned char)in[i];
        if (ch == '=') break;
        int v = T[ch];
        if (v < 0) continue;
        acc = (acc << 6) | (unsigned)v; bits += 6;
        if (bits >= 8) { bits -= 8; out.push_back((unsigned char)(acc >> bits)); }
    }
    return !out.empty();
}

static bool ep_verify(const std::string &msg, const unsigned char *sig,
                      size_t siglen) {
    if (siglen != 64) return false;
    EVP_PKEY *pkey =
        EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, EP_PUBKEY, 32);
    if (!pkey) return false;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    bool ok = false;
    if (ctx && EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey) == 1)
        ok = EVP_DigestVerify(ctx, sig, siglen,
                              (const unsigned char *)msg.data(),
                              msg.size()) == 1;
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return ok;
}

// GET rapido de un solo intento para la config (no bloquea el arranque
// si no hay red: 8 s de conexion, 25 s total como maximo).
static bool ep_fetch(const std::string &url, std::string &body) {
    body.clear();
    CURL *c = curl_easy_init();
    if (!c) return false;
    curl_easy_setopt(c, CURLOPT_URL, url.c_str());
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, wr_cb);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &body);
    curl_easy_setopt(c, CURLOPT_USERAGENT, FLKICK_UA);
    curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT, 8L);
    curl_easy_setopt(c, CURLOPT_TIMEOUT, 25L);
    curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(c, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
    curl_easy_setopt(c, CURLOPT_NOSIGNAL, 1L);
    CURLcode cc = curl_easy_perform(c);
    long code = 0;
    if (cc == CURLE_OK) curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &code);
    curl_easy_cleanup(c);
    return cc == CURLE_OK && code == 200 && !body.empty();
}

static bool https_only(const std::string &u) {
    return u.compare(0, 8, "https://") == 0;
}

// Descarga endpoints.json, verifica la firma Ed25519 y, si es valida,
// sustituye los endpoints compilados. Idempotente: solo corre una vez.
static void load_remote_endpoints() {
    if (g_ep_state) return;
    g_ep_state = 2;  // respaldo compilado por defecto
    const char *ov = getenv("FLKICK_EP_URL");  // gancho para pruebas
    std::string url = (ov && *ov) ? ov : EP_CONFIG_URL;
    // En pruebas (solo localhost via FLKICK_EP_URL) se permite http.
    bool is_test = url.compare(0, 16, "http://127.0.0.1") == 0 ||
                   url.compare(0, 16, "http://localhost") == 0;
    std::string body;
    if (!ep_fetch(url, body)) return;
    json_object *root = json_tokener_parse(body.c_str());
    if (!root) return;
    const char *al = js_str(root, "api_list");
    const char *ac = js_str(root, "api_chan");
    const char *as = js_str(root, "api_search");
    const char *tk = js_str(root, "ts_api_key");
    const char *sg = js_str(root, "sig");
    bool ok = false;
    if (*al && *ac && *as && *tk && *sg &&
        (is_test || (https_only(al) && https_only(ac) && https_only(as)))) {
        // Mensaje firmado: campos unidos por \n (mismo orden al firmar).
        std::string msg = std::string(al) + "\n" + ac + "\n" + as + "\n" +
                          tk + "\n";
        std::vector<unsigned char> sig;
        if (b64_dec(sg, sig) && ep_verify(msg, &sig[0], sig.size())) {
            API_LIST = al; API_CHAN = ac; API_SEARCH = as; TS_API_KEY = tk;
            ok = true;
        }
    }
    json_object_put(root);
    if (ok) g_ep_state = 1;
}

static std::string lower_of(std::string s) {
    for (size_t i = 0; i < s.size(); i++)
        if (s[i] >= 'A' && s[i] <= 'Z') s[i] += 32;
    return s;
}

static bool is_cloudflare(const HttpRes &r) {
    if (r.code != 403 && r.code != 503 && r.code != 429) return false;
    std::string b = lower_of(r.body.substr(0, 8192));
    return b.find("cloudflare") != std::string::npos ||
           b.find("challenge") != std::string::npos ||
           b.find("just a moment") != std::string::npos ||
           b.find("cf-ray") != std::string::npos;
}

static std::string net_error(const HttpRes &r, const char *que) {
    char buf[384];
    std::string host = host_of(r.url);
    if (r.curl_err)
        // Diagnostico con una foto: host que fallo y codigo curl exacto.
        snprintf(buf, sizeof(buf),
                 "Sin conexion con Kick (%s): fallo %s "
                 "(curl %d, %d intentos).",
                 que, host.c_str(), r.curl_err, r.attempts);
    else if (is_cloudflare(r))
        snprintf(buf, sizeof(buf),
                 "Cloudflare rechazo la peticion desde esta IP (HTTP %ld). "
                 "Intenta de nuevo en un rato.", r.code);
    else
        snprintf(buf, sizeof(buf), "Kick respondio HTTP %ld en %s (%s).",
                 r.code, que, host.c_str());
    return buf;
}

// ---------------------------------------------------------------- json
static const char *js_str(json_object *o, const char *k) {
    json_object *v = nullptr;
    if (o && json_object_object_get_ex(o, k, &v) && v) {
        const char *s = json_object_get_string(v);
        return s ? s : "";
    }
    return "";
}
static long js_int(json_object *o, const char *k) {
    json_object *v = nullptr;
    if (o && json_object_object_get_ex(o, k, &v) && v)
        return json_object_get_int64(v);
    return 0;
}
static json_object *js_obj(json_object *o, const char *k) {
    json_object *v = nullptr;
    if (o && json_object_object_get_ex(o, k, &v)) return v;
    return nullptr;
}

static void parse_list_page(json_object *root, std::vector<Row> &out) {
    json_object *data = js_obj(root, "data");
    json_object *arr = js_obj(data, "livestreams");
    if (!arr) return;
    size_t n = json_object_array_length(arr);
    for (size_t i = 0; i < n; i++) {
        json_object *it = json_object_array_get_idx(arr, i);
        json_object *st = js_obj(it, "streamer");
        json_object *ch = js_obj(st, "channel");
        json_object *us = js_obj(st, "user");
        json_object *md = js_obj(it, "metadata");
        json_object *cat = js_obj(md, "category");
        Row r;
        r.slug = js_str(ch, "slug");
        r.user = js_str(us, "username");
        if (r.user.empty()) r.user = r.slug;
        r.title = js_str(md, "title");
        r.viewers = js_int(it, "viewers_count");
        r.category = js_str(cat, "name");
        if (!r.slug.empty()) out.push_back(r);
    }
}

// ---------------------------------------------------------------- trabajos
enum JobKind {
    JOB_LIST, JOB_CHANNEL, JOB_CATEGORY, JOB_PLAY, JOB_SUGGEST,
    JOB_VOD_LIST, JOB_VOD_PLAY
};

struct JobResult {
    JobKind kind;
    bool ok = false;
    std::string query;   // texto que origino el job (sugerencias)
    bool notfound = false;
    std::string err;
    std::string note;
    std::vector<Row> rows;
    std::vector<Vod> vods;
    std::string play_url;
    int play_height = 0;
    std::string play_label;
    bool via_master = false;  // la URL es el master: ffmpeg lo resuelve
};

struct JobArg {
    JobKind kind;
    std::string query;
};

static void awake_cb(void *p);
static void vod_refresh_ui();
static void run_job(JobKind kind, const std::string &q, const char *msg,
                    bool silent = false);

static std::string api_list_url(const std::string &cursor) {
    std::string u = API_LIST;
    if (!cursor.empty()) {
        CURL *c = curl_easy_init();
        char *enc = c ? curl_easy_escape(c, cursor.c_str(), 0) : nullptr;
        u += "?cursor=";
        u += enc ? enc : cursor.c_str();
        if (enc) curl_free(enc);
        if (c) curl_easy_cleanup(c);
    }
    return u;
}

static bool fetch_lives(int max_pages, const std::string &fslug,
                        const std::string &ftxt, JobResult *res) {
    std::string cursor;
    for (int page = 0; page < max_pages; page++) {
        HttpRes r = http_get(api_list_url(cursor));
        if (r.curl_err || r.code != 200) {
            res->err = net_error(r, "el listado de directos");
            return false;
        }
        json_object *root = json_tokener_parse(r.body.c_str());
        if (!root) { res->err = "Respuesta de Kick no valida (JSON)."; return false; }
        std::vector<Row> all;
        parse_list_page(root, all);
        json_object *data = js_obj(root, "data");
        const char *nc = js_str(data, "next_cursor");
        cursor = nc ? nc : "";
        json_object_put(root);
        for (size_t i = 0; i < all.size(); i++) {
            if (!fslug.empty()) {
                std::string cat = lower_of(all[i].category);
                std::string usr = lower_of(all[i].user);
                std::string ft = lower_of(ftxt);
                if (cat == lower_of(fslug) || cat.find(ft) != std::string::npos ||
                    usr.find(ft) != std::string::npos)
                    res->rows.push_back(all[i]);
            } else {
                res->rows.push_back(all[i]);
            }
        }
        if (cursor.empty()) break;
    }
    return true;
}

// ---------------------------------------------------------------- HLS
struct Variant { int height; std::string url; };

static std::string resolve_url(const std::string &base, const std::string &rel) {
    if (rel.find("://") != std::string::npos) return rel;
    std::string b = base.substr(0, base.find('?'));
    if (!rel.empty() && rel[0] == '/') {
        size_t p = b.find("://");
        size_t h = (p == std::string::npos) ? 0 : b.find('/', p + 3);
        return (h == std::string::npos ? b : b.substr(0, h)) + rel;
    }
    size_t s = b.rfind('/');
    return (s == std::string::npos ? b : b.substr(0, s + 1)) + rel;
}

static void parse_variants(const std::string &master, const std::string &base,
                           std::vector<Variant> &out) {
    std::string pending;
    int pending_h = 0;
    size_t pos = 0;
    while (pos <= master.size()) {
        size_t nl = master.find('\n', pos);
        std::string ln = master.substr(
            pos, nl == std::string::npos ? std::string::npos : nl - pos);
        if (!ln.empty() && ln[ln.size() - 1] == '\r') ln.erase(ln.size() - 1);
        pos = (nl == std::string::npos) ? master.size() + 1 : nl + 1;
        if (ln.find("#EXT-X-STREAM-INF:") == 0) {
            pending = ln;
            pending_h = 0;
            size_t rp = ln.find("RESOLUTION=");
            if (rp != std::string::npos) {
                int w = 0, h = 0;
                if (sscanf(ln.c_str() + rp + 11, "%dx%d", &w, &h) == 2)
                    pending_h = h;
            }
            if (!pending_h) {  // respaldo: NAME="480p"
                size_t np = ln.find("NAME=\"");
                if (np != std::string::npos) pending_h = atoi(ln.c_str() + np + 6);
            }
        } else if (!ln.empty() && ln[0] != '#' && !pending.empty()) {
            if (pending_h > 0) {
                Variant v;
                v.height = pending_h;
                v.url = resolve_url(base, ln);
                out.push_back(v);
            }
            pending.clear();
        }
    }
}

// exacta; si no, inmediata inferior; si tampoco, la mas baja
static const Variant *choose_variant(const std::vector<Variant> &v, int want) {
    const Variant *exact = nullptr, *lower = nullptr, *lowest = nullptr;
    for (size_t i = 0; i < v.size(); i++) {
        if (v[i].height == want) exact = &v[i];
        if (v[i].height < want && (!lower || v[i].height > lower->height))
            lower = &v[i];
        if (!lowest || v[i].height < lowest->height) lowest = &v[i];
    }
    return exact ? exact : (lower ? lower : lowest);
}

static void *job_thread(void *vp) {
    JobArg *arg = (JobArg *)vp;
    JobResult *res = new JobResult();
    res->kind = arg->kind;
    load_remote_endpoints();  // 0.6: config remota firmada (una sola vez)

    if (arg->kind == JOB_VOD_LIST) {
        res->query = arg->query;
        HttpRes r = http_get(API_CHAN + arg->query + "/videos");
        if (r.curl_err || r.code != 200) {
            res->err = net_error(r, "las grabaciones");
        } else {
            json_object *root = json_tokener_parse(r.body.c_str());
            if (!root || json_object_get_type(root) != json_type_array) {
                res->err = "Kick no devolvio una lista valida de grabaciones.";
            } else {
                size_t n = json_object_array_length(root);
                for (size_t i = 0; i < n; ++i) {
                    json_object *item = json_object_array_get_idx(root, i);
                    if (!item) continue;
                    json_object *live = nullptr;
                    if (json_object_object_get_ex(item, "is_live", &live)
                        && live && json_object_get_boolean(live))
                        continue;
                    Vod v;
                    v.source = js_str(item, "source");
                    if (v.source.find("https://") != 0) continue;
                    v.title = js_str(item, "session_title");
                    if (v.title.empty()) v.title = "Grabacion sin titulo";
                    v.date = js_str(item, "created_at");
                    v.duration_ms = js_int(item, "duration");
                    v.views = js_int(item, "views");
                    res->vods.push_back(v);
                }
                res->ok = true;
            }
            if (root) json_object_put(root);
        }
    } else if (arg->kind == JOB_VOD_PLAY) {
        if (arg->query.find("https://") != 0) {
            res->err = "Direccion de grabacion no valida.";
        } else {
            res->play_url = arg->query;
            res->play_label = "Grabacion";
            HttpRes m = http_get(arg->query);
            if (!m.curl_err && m.code == 200) {
                std::vector<Variant> vars;
                parse_variants(m.body, arg->query, vars);
                if (!vars.empty()) {
                    const Variant *v = choose_variant(vars, g_quality);
                    res->play_url = v->url;
                    res->play_height = v->height;
                    char label[80];
                    snprintf(label, sizeof(label),
                             "Grabacion - %dp", v->height);
                    res->play_label = label;
                }
            }
            res->ok = true;
        }
    } else if (arg->kind == JOB_LIST) {
        if (fetch_lives(1, "", "", res)) {
            res->ok = true;
            char b[96];
            snprintf(b, sizeof(b), "%zu directos en vivo - via anonima, sin cuenta",
                     res->rows.size());
            res->note = b;
        }
    } else if (arg->kind == JOB_CHANNEL || arg->kind == JOB_PLAY) {
        std::string slug = arg->query;
        HttpRes r = http_get(API_CHAN + slug);
        if (r.curl_err) {
            res->err = net_error(r, "el canal");
        } else if (r.code == 404) {
            res->notfound = true;
            res->err = "El canal buscado no existe en Kick (HTTP 404).";
        } else if (r.code != 200) {
            res->err = net_error(r, "el canal");
        } else {
            json_object *root = json_tokener_parse(r.body.c_str());
            if (!root) {
                res->err = "Respuesta de Kick no valida (JSON).";
            } else {
                json_object *us = js_obj(root, "user");
                std::string user = js_str(us, "username");
                if (user.empty()) user = slug;
                std::string pb = js_str(root, "playback_url");
                json_object *lsj = js_obj(root, "livestream");
                bool live = false;
                if (lsj) {
                    json_object *lv = nullptr;
                    if (json_object_object_get_ex(lsj, "is_live", &lv) && lv)
                        live = json_object_get_boolean(lv);
                    else
                        live = true;  // hay objeto livestream: esta en vivo
                }
                if (!live) {
                    // 0.7: el canal existe pero esta apagado: se muestra
                    // en la lista con punto rojo (live=false).
                    Row row;
                    row.slug = slug;
                    row.user = user;
                    row.live = false;
                    res->rows.push_back(row);
                    res->ok = true;
                    res->note = std::string("\xc2\xab") + user +
                                "\xc2\xbb no est\xc3\xa1 en directo ahora.";
                } else if (pb.empty()) {
                    res->err = "Kick no entrego la URL de reproduccion del canal.";
                } else if (arg->kind == JOB_CHANNEL) {
                    Row row;
                    row.slug = slug;
                    row.user = user;
                    row.title = js_str(lsj, "session_title");
                    row.viewers = js_int(lsj, "viewer_count");
                    json_object *cats = js_obj(lsj, "categories");
                    if (cats && json_object_array_length(cats) > 0)
                        row.category = js_str(
                            json_object_array_get_idx(cats, 0), "name");
                    res->rows.push_back(row);
                    res->ok = true;
                    // Sin esto la barra se quedaba en «Buscando canal…»
                    // aunque la fila ya estuviera en la tabla.
                    res->note = std::string("\xc2\xab") + user +
                                "\xc2\xbb esta en directo ahora.";
                } else {  // JOB_PLAY: master + variante dentro del hilo
                    HttpRes m = http_get(pb);
                    bool have_variant = false;
                    if (!m.curl_err && m.code == 200) {
                        std::vector<Variant> vars;
                        parse_variants(m.body, pb, vars);
                        if (!vars.empty()) {
                            const Variant *v = choose_variant(vars, g_quality);
                            res->ok = true;
                            res->play_url = v->url;
                            res->play_height = v->height;
                            char lb[160];
                            snprintf(lb, sizeof(lb), "%s - %dp",
                                     user.c_str(), v->height);
                            res->play_label = lb;
                            have_variant = true;
                        }
                    }
                    if (!have_variant) {
                        // Fallback (0.2): ni preguntar. Si tras los
                        // reintentos el master no baja (transporte caido
                        // o el CDN rechaza la URL que haya) o no trae
                        // variantes legibles, se le entrega la URL
                        // master tal cual a ffmpeg y que el resuelva
                        // el HLS; el estado lo avisa («via master»).
                        res->ok = true;
                        res->via_master = true;
                        res->play_url = pb;
                        res->play_height = 0;
                        res->play_label = user;
                    }
                }
                json_object_put(root);
            }
        }
    } else if (arg->kind == JOB_CATEGORY) {
        if (fetch_lives(6, arg->query, arg->query, res)) {
            res->ok = true;
            char b[192];
            snprintf(b, sizeof(b),
                     "%zu directos para \xc2\xab%s\xc2\xbb (filtrado local del top global).",
                     res->rows.size(), arg->query.c_str());
            res->note = b;
        }
    } else if (arg->kind == JOB_SUGGEST) {
        // Sugerencias EN VIVO de toda la plataforma (Typesense, el
        // buscador de la web). Solo candidatas: is_live := true y sin
        // baneo, ordenadas por seguidores (el indice no trae
        // espectadores). El veredicto lo da api/v2 en Enter/REPRODUCIR.
        res->query = arg->query;
        CURL *ce = curl_easy_init();
        char *eq = ce ? curl_easy_escape(ce, arg->query.c_str(), 0) : nullptr;
        std::string url = std::string(API_SEARCH) + "?q=" +
                          (eq ? eq : arg->query.c_str()) +
                          "&query_by=username"
                          "&filter_by=is_live:=true%20%26%26%20is_banned:=false"
                          "&sort_by=followers_count:desc&per_page=10";
        if (eq) curl_free(eq);
        if (ce) curl_easy_cleanup(ce);
        HttpRes r = http_get(url, "X-TYPESENSE-API-KEY", TS_API_KEY.c_str());
        if (!r.curl_err && r.code == 200) {
            json_object *root = json_tokener_parse(r.body.c_str());
            if (root) {
                json_object *hits = js_obj(root, "hits");
                std::set<std::string> seen;
                if (hits) {
                    size_t n = json_object_array_length(hits);
                    for (size_t i = 0; i < n; i++) {
                        json_object *doc =
                            js_obj(json_object_array_get_idx(hits, i),
                                   "document");
                        if (!doc) continue;
                        json_object *lv = nullptr;
                        bool live =
                            json_object_object_get_ex(doc, "is_live", &lv) &&
                            lv && json_object_get_boolean(lv);
                        if (!live) continue;  // apagado: no se sugiere
                        Row row;
                        row.slug = js_str(doc, "slug");
                        row.user = js_str(doc, "username");
                        if (row.user.empty()) row.user = row.slug;
                        if (row.slug.empty() || seen.count(row.slug))
                            continue;
                        seen.insert(row.slug);
                        res->rows.push_back(row);
                    }
                }
                json_object_put(root);
                res->ok = true;  // tambien si salen 0: no es un error
            }
        }
    }

    Fl::awake(awake_cb, res);
    delete arg;
    return nullptr;
}

// ---------------------------------------------------------------- player
static void lock_ui(bool lock);  // 0.7: definida junto a busy(), mas abajo
static void set_status(const std::string &s) {
    static char buf[512];
    snprintf(buf, sizeof(buf), "%s", s.c_str());
    g_status->label(buf);
    g_status->redraw();
}

static double now_s() {
    struct timeval tv;
    gettimeofday(&tv, nullptr);
    return tv.tv_sec + tv.tv_usec / 1e6;
}

static void player_launch(const std::string &url, const std::string &label,
                          bool via_master = false) {
    if (g_player_pid > 0) {
        kill(-g_player_pid, SIGTERM);
        waitpid(g_player_pid, nullptr, 0);
        g_player_pid = -1;
    }
    // Con el fallback el master va pelado a ffmpeg y la calidad ya no
    // esta forzada: la etiqueta lo deja claro en todo el estado.
    g_playing_label = via_master ? label + " (via master)" : label;
    // Tuberia ffmpeg -> mplayer (ver el comentario de cabecera): ffmpeg
    // demuxa el HLS por HTTPS con reconexiones y entrega MPEG-TS limpio;
    // mplayer solo decodifica y muestra. Ambos procesos quedan en el
    // mismo grupo (setsid) para que Detener mate los dos a la vez.
    std::string uq = url;
    for (size_t i = 0; (i = uq.find('\'', i)) != std::string::npos; i += 4)
        uq.replace(i, 1, "'\\''");
    char cmdb[4096];
    snprintf(cmdb, sizeof(cmdb),
             "ffmpeg -hide_banner -loglevel error -user_agent '%s' "
             "-reconnect 1 -reconnect_streamed 1 -reconnect_delay_max 5 "
             "-i '%s' -c copy -f mpegts pipe:1 | "
             "exec mpv --no-config --fullscreen "
             "--demuxer=lavf --demuxer-lavf-format=mpegts "
             "--vo=xv --ao=alsa,pulse,null "
             "--cache=yes --cache-secs=10 "
             "--framedrop=vo "
             "-",
             FLKICK_UA, uq.c_str());
    pid_t pid = fork();
    if (pid == 0) {
        setsid();
        FILE *dn = fopen("/dev/null", "w");
        if (dn) { dup2(fileno(dn), 1); dup2(fileno(dn), 2); }
        execlp("/bin/sh", "sh", "-c", cmdb, (char *)nullptr);
        _exit(127);
    }
    if (pid > 0) {
        g_player_pid = pid;
        g_player_t0 = now_s();
        g_user_stopped = false;
        lock_ui(true);  // 0.7: solo Detener e Info activos al reproducir
        set_status(via_master
                       ? std::string("Reproduciendo via master: ") + label
                       : std::string("Reproduciendo: ") + label);
    } else {
        set_status("No se pudo lanzar MPV.");
    }
}

// VOD: MPV recibe HLS directamente para conservar pausa y busqueda.
static void player_launch_vod(const std::string &url,
                              const std::string &label) {
    if (g_player_pid > 0) {
        kill(-g_player_pid, SIGTERM);
        waitpid(g_player_pid, nullptr, 0);
        g_player_pid = -1;
    }
    pid_t pid = fork();
    if (pid == 0) {
        setsid();
        FILE *dn = fopen("/dev/null", "w");
        if (dn) {
            dup2(fileno(dn), 1);
            dup2(fileno(dn), 2);
            fclose(dn);
        }
        execlp("mpv", "mpv",
               "--no-config", "--fullscreen",
               "--vo=xv", "--ao=alsa,pulse,null",
               "--cache=yes", "--cache-secs=10",
               "--framedrop=vo", url.c_str(), (char *)nullptr);
        _exit(127);
    }
    if (pid > 0) {
        g_player_pid = pid;
        g_player_t0 = now_s();
        g_user_stopped = false;
        g_playing_label = label;
        lock_ui(true);
        set_status(std::string("Reproduciendo: ") + label);
    } else {
        logo_spin_stop();
        set_status("No se pudo lanzar MPV para grabaciones.");
    }
}
static void player_stop(bool silent) {
    if (g_player_pid > 0) {
        g_user_stopped = true;
        kill(-g_player_pid, SIGTERM);
        waitpid(g_player_pid, nullptr, 0);
        g_player_pid = -1;
        lock_ui(false);  // 0.7: mplayer cerrado, app desbloqueada
        logo_spin_stop();  // 0.7
        if (!silent) set_status("Detenido.");
    }
}

static void watch_cb(void *) {
    // Debounce de sugerencias: ~0,5 s despues del ultimo tecleo (este
    // watch pasa cada 0,5 s) y sin solapar dos JOB_SUGGEST.
    if (!g_sugg_queued.empty() && g_sugg_inflight.empty() &&
        g_sugg_queued != g_sugg_for && now_s() - g_last_key_t >= 0.5) {
        g_sugg_inflight = g_sugg_queued;
        run_job(JOB_SUGGEST, g_sugg_queued, "", true);
    }
    if (g_player_pid > 0) {
        int st = 0;
        pid_t r = waitpid(g_player_pid, &st, WNOHANG);
        if (r == g_player_pid) {
            double up = now_s() - g_player_t0;
            std::string lbl = g_playing_label;
            g_player_pid = -1;
            lock_ui(false);  // 0.7: mplayer cerrado, app desbloqueada
            logo_spin_stop();  // 0.7
            if (g_user_stopped) {
                // ya informado
            } else if (up < 6.0) {
                set_status(std::string("No se pudo reproducir ") + lbl +
                           ". Revisa la conexion.");
            } else {
                set_status(std::string("Fin de la reproduccion: ") + lbl);
            }
        } else if (r == 0 && now_s() - g_player_t0 > 5.0) {
            logo_spin_stop();  // 0.7: video ya visible, quita el efecto
        }
    }
    Fl::repeat_timeout(0.5, watch_cb);
}

// ---------------------------------------------------------------- tabla
static std::string fmt_viewers(long n) {
    char raw[32];
    snprintf(raw, sizeof(raw), "%ld", n);
    std::string s = raw, out;
    int cnt = 0;
    for (int i = (int)s.size() - 1; i >= 0; i--) {
        out.insert(out.begin(), s[i]);
        if (++cnt % 3 == 0 && i > 0) out.insert(out.begin(), ' ');
    }
    return out;
}

// Pulgar arriba dibujado (la fuente del banco no garantiza el emoji):
// inactivo = silueta clara con contorno negro grueso, como el PNG;
// activo = relleno verde Kick, el mismo verde del boton REPRODUCIR.
static void draw_thumb(int X, int Y, int W, int H, bool active) {
    static const double pts[][2] = {
        {5, 21}, {5, 12}, {8, 12}, {10, 4}, {13, 4}, {15, 7},
        {14, 11}, {20, 11}, {21, 13}, {20.5, 16}, {21, 18}, {20, 21},
    };
    const int cx = X + (W - 24) / 2, cy = Y + (H - 24) / 2;
    fl_color(active ? kick_green() : fl_rgb_color(238, 238, 238));
    fl_begin_polygon();
    for (size_t i = 0; i < sizeof(pts) / sizeof(pts[0]); i++)
        fl_vertex(cx + pts[i][0], cy + pts[i][1]);
    fl_end_polygon();
    fl_color(fl_rgb_color(10, 10, 10));
    fl_line_style(FL_SOLID, 2);
    fl_begin_loop();
    for (size_t i = 0; i < sizeof(pts) / sizeof(pts[0]); i++)
        fl_vertex(cx + pts[i][0], cy + pts[i][1]);
    fl_end_loop();
    fl_line_style(FL_SOLID, 1);
    fl_begin_line();
    fl_vertex(cx + 15.5, cy + 14.5);
    fl_vertex(cx + 20, cy + 14.5);
    fl_end_line();
    fl_begin_line();
    fl_vertex(cx + 15.5, cy + 17.5);
    fl_vertex(cx + 20, cy + 17.5);
    fl_end_line();
}

static void toggle_like(int r);  // definido en las acciones
static void update_favs_btn();  // definido en las acciones
static void busy(bool b);       // definido en las acciones

class KickTable : public Fl_Table_Row {
public:
    int handle(int e) override {
        if (e == FL_PUSH && Fl::event_button() == FL_LEFT_MOUSE) {
            int R = -1, C = -1;
            ResizeFlag rf = (ResizeFlag)0;
            TableContext tc = cursor2rowcol(R, C, rf);
            if (tc == CONTEXT_CELL && C == 4 && R >= 0 &&
                R < (int)g_view.size()) {
                select_row(R);
                toggle_like(R);
                return 1;
            }
        }
        return Fl_Table_Row::handle(e);
    }

    KickTable(int X, int Y, int W, int H) : Fl_Table_Row(X, Y, W, H) {
        cols(5);
        col_header(1);
        col_resize(1);
        row_header(0);
        rows(0);
        type(SELECT_SINGLE);
        end();
    }

protected:
    void draw_cell(TableContext ctx, int R, int C, int X, int Y, int W,
                   int H) override {
        const Palette &P = pal();
        static const char *hdrs[] = {"CANAL", "TITULO DEL DIRECTO",
                                     "ESPECT.", "CATEGORIA", "LIKE"};
        switch (ctx) {
        case CONTEXT_STARTPAGE:
            fl_font(FL_HELVETICA, 13);
            return;
        case CONTEXT_COL_HEADER:
            fl_push_clip(X, Y, W, H);
            fl_draw_box(FL_FLAT_BOX, X, Y, W, H, P.header);
            fl_color(P.txt);
            fl_font(FL_HELVETICA_BOLD, 12);
            fl_draw(hdrs[C], X + 8, Y, W - 16, H, FL_ALIGN_LEFT);
            fl_pop_clip();
            return;
        case CONTEXT_CELL: {
            fl_push_clip(X, Y, W, H);
            bool sel = row_selected(R) != 0;
            Fl_Color bg = sel ? P.sel : ((R % 2) ? P.row_alt : P.row);
            fl_draw_box(FL_FLAT_BOX, X, Y, W, H, bg);
            if (R < 0 || R >= (int)g_view.size()) { fl_pop_clip(); return; }
            const Row &r = g_view[R];
            fl_color(sel ? P.sel_txt : P.txt);
            if (C == 0) {
                // punto verde = en vivo, rojo = apagado (0.7)
                fl_color(r.live ? fl_rgb_color(37, 201, 55)
                                : fl_rgb_color(220, 40, 40));
                fl_begin_polygon();
                fl_circle(X + 10, Y + H / 2, 4.5);
                fl_end_polygon();
                fl_color(sel ? P.sel_txt : P.txt);
                fl_font(FL_HELVETICA_BOLD, 13);
                fl_draw(r.user.c_str(), X + 20, Y, W - 24, H, FL_ALIGN_LEFT);
            } else if (C == 1) {
                fl_font(FL_HELVETICA, 13);
                fl_draw(r.title.c_str(), X + 8, Y, W - 16, H, FL_ALIGN_LEFT);
            } else if (C == 2) {
                fl_font(FL_HELVETICA, 13);
                std::string v = fmt_viewers(r.viewers);
                fl_draw(v.c_str(), X + 4, Y, W - 12, H, FL_ALIGN_LEFT);
            } else if (C == 3) {
                fl_font(FL_HELVETICA, 13);
                fl_color(sel ? P.sel_txt : P.txt);
                fl_draw(r.category.c_str(), X + 8, Y, W - 16, H,
                        FL_ALIGN_LEFT);
            } else {
                draw_thumb(X, Y, W, H, g_likes.count(r.slug) != 0);
            }
            fl_pop_clip();
            return;
        }
        default:
            return;
        }
    }
};

static KickTable *g_table = nullptr;

static int selected_row() {
    for (int r = 0; r < (int)g_view.size(); r++)
        if (g_table->row_selected(r)) return r;
    return -1;
}

// ---------------------------------------------------------------- acciones
static void apply_filter(bool announce);
static void update_favs_btn();

static void toggle_like(int r) {
    if (r < 0 || r >= (int)g_view.size()) return;
    const std::string slug = g_view[r].slug;
    const std::string user = g_view[r].user;
    if (g_likes.count(slug)) {
        g_likes.erase(slug);
        set_status("Like quitado de " + user + ".");
    } else {
        g_likes.insert(slug);
        set_status("Me gusta: " + user +
                   " (pulgar verde, canal en Favoritos).");
    }
    cfg_save();
    if (g_favs_mode) apply_filter(false);
    g_table->redraw();
}

static void update_favs_btn() {
    if (!g_btn_favs) return;
    if (g_favs_mode) {
        g_btn_favs->color(kick_green());
        g_btn_favs->labelcolor(fl_rgb_color(10, 30, 5));
    } else {
        const Palette &P = pal();
        g_btn_favs->color(P.btn);
        g_btn_favs->labelcolor(P.txt);
    }
    g_btn_favs->box(FL_BORDER_BOX);
    g_lbl_head->copy_label(g_favs_mode
                               ? "Favoritos - solo tus canales con like"
                               : "En vivo ahora - sin cuenta (via anonima)");
    g_btn_favs->redraw();
}

static void favs_cb(Fl_Widget *, void *) {
    // 0.7: Favoritos muestra solo los canales con like que estan en
    // directo (filtro local de g_rows). No se borra el filtro.
    g_favs_mode = !g_favs_mode;
    update_favs_btn();
    apply_filter(false);
    set_status(g_favs_mode
                   ? "Favoritos: canales guardados, conectados o desconectados."
                   : "Directos: lista completa.");
}

static void busy(bool b) {
    if (b) {
        g_btn_search->deactivate();
        g_btn_list->deactivate();
        g_btn_favs->deactivate();
        g_btn_play->deactivate();
    } else {
        g_btn_search->activate();
        g_btn_list->activate();
        g_btn_favs->activate();
        g_btn_play->activate();
    }
}

static void lock_ui(bool lock) {
    // 0.7: mientras mplayer reproduce, solo quedan activos Detener
    // (g_btn_stop) e Info (g_btn_info); el resto se bloquea hasta que
    // mplayer se cierra.
    if (lock) {
        g_input->deactivate();
        g_btn_search->deactivate();
        g_btn_list->deactivate();
        g_btn_favs->deactivate();
        g_btn_theme->deactivate();
        g_btn_play->deactivate();
        g_btn_quality->deactivate();
        g_table->deactivate();
    } else {
        g_input->activate();
        g_btn_search->activate();
        g_btn_list->activate();
        g_btn_favs->activate();
        g_btn_theme->activate();
        g_btn_play->activate();
        g_btn_quality->activate();
        g_table->activate();
    }
}

static void run_job(JobKind kind, const std::string &q, const char *msg,
                    bool silent) {
    if (!silent) {
        busy(true);
        set_status(msg);
    }
    JobArg *a = new JobArg();
    a->kind = kind;
    a->query = q;
    pthread_t th;
    if (pthread_create(&th, nullptr, job_thread, a) == 0) {
        pthread_detach(th);
    } else {
        delete a;
        busy(false);
        set_status("No se pudo crear el hilo de red.");
    }
}

static std::string trim(const std::string &s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    size_t b = s.find_last_not_of(" \t\r\n");
    return (a == std::string::npos) ? "" : s.substr(a, b - a + 1);
}

static std::string slugify(std::string s) {
    s = lower_of(s);
    std::string out;
    for (size_t i = 0; i < s.size(); i++) {
        char c = s[i];
        if (c == ' ' || c == '_') c = '-';
        if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-')
            out += c;
    }
    return out;
}

static void sugg_clear() {
    g_sugg_rows.clear();
    g_sugg_for.clear();
    g_sugg_inflight.clear();
    g_sugg_queued.clear();
}

static void do_list() {
    sugg_clear();
    run_job(JOB_LIST, "", "Cargando directos...");
}

static void do_search() {
    // 0.7: Enter/Buscar comprueba un canal concreto por API (api/v2):
    // si esta en directo aparece con punto verde; si esta apagado, con
    // punto rojo. Si no existe como canal, se intenta como categoria.
    std::string q = trim(g_input->value());
    if (q.empty()) { do_list(); return; }
    sugg_clear();
    run_job(JOB_CHANNEL, slugify(q), "Buscando canal...");
}

static void do_play_row(int r) {
    if (r < 0 || r >= (int)g_view.size()) {
        set_status("Elige un directo de la lista.");
        return;
    }
    if (!g_view[r].live) {
        // 0.7: canal apagado (punto rojo): no se puede reproducir
        set_status("Ese canal no est\xc3\xa1 en directo ahora.");
        return;
    }
    char msg[160];
    snprintf(msg, sizeof(msg), "Obteniendo directo de %s...",
             g_view[r].user.c_str());
    logo_spin_start();  // 0.7: efecto de carga en el icono K
    run_job(JOB_PLAY, g_view[r].slug, msg);
}

static void play_cb(Fl_Widget *, void *) { do_play_row(selected_row()); }
static void stop_cb(Fl_Widget *, void *) { player_stop(false); }
static void search_cb(Fl_Widget *, void *) { do_search(); }
static void list_cb(Fl_Widget *, void *) {
    if (g_favs_mode) {  // Directos saca de Favoritos al instante
        g_favs_mode = false;
        update_favs_btn();
        apply_filter(false);
        set_status("Directos: lista completa.");
        return;
    }
    do_list();
}

static void table_cb(Fl_Widget *, void *) {
    if (g_table->callback_context() != Fl_Table::CONTEXT_TABLE) return;
    int R = g_table->callback_row();
    if (R >= 0 && Fl::event_clicks() > 0) do_play_row(R);
}

// ------------------------------------------------------- filtro al teclear
// Al escribir en «Canal o categoría» la tabla se filtra AL MOMENTO y en
// local (sin red) sobre los directos ya cargados: coinciden canal o
// titulo (solo canal, sin categoria); primero los que empiezan por lo
// escrito y luego los que solo lo contienen. Con texto, la lista va en
// orden alfabetico; sin texto se mantiene el orden por espectadores de
// la API. Detras van las sugerencias EN VIVO de la plataforma para ese
// mismo texto (si ya llegaron), sin duplicar y pasando tambien por el
// filtro de Favoritos si el modo esta activo.
// Al borrar el texto vuelve la lista completa. Enter/Buscar comprueba
// por API un canal concreto.
static bool g_has_filter = false;

static void apply_filter(bool announce) {
    std::string typed = trim(g_input->value());
    std::string q = lower_of(typed);
    // 0.7: en modo Favoritos la base son los canales con like que
    // estan en directo (de g_rows); fuera de ahi, g_rows completa.
    std::vector<Row> base;
    if (g_favs_mode) {
        std::set<std::string> found;

        for (size_t i = 0; i < g_rows.size(); i++) {
            if (g_likes.count(g_rows[i].slug)) {
                base.push_back(g_rows[i]);
                found.insert(g_rows[i].slug);
            }
        }

        for (const std::string &slug : g_likes) {
            if (found.count(slug)) continue;

            Row row;
            row.slug = slug;
            row.user = slug;
            row.title = "Canal desconectado";
            row.category = "-";
            row.viewers = 0;
            row.live = false;
            base.push_back(row);
        }
    } else {
        base = g_rows;
    }
    g_view.clear();
    size_t sugg_added = 0;
    if (q.empty()) {
        g_view = base;
    } else {
        std::set<std::string> shown;
        for (int pass = 0; pass < 2; pass++)
            for (size_t i = 0; i < base.size(); i++) {
                std::string u = lower_of(base[i].user);
                std::string t = lower_of(base[i].title);
                bool starts = u.compare(0, q.size(), q) == 0 ||
                              t.compare(0, q.size(), q) == 0;
                bool has = u.find(q) != std::string::npos ||
                           t.find(q) != std::string::npos;
                if ((pass == 0 && starts) || (pass == 1 && has && !starts)) {
                    g_view.push_back(base[i]);
                    shown.insert(base[i].slug);
                }
            }
        // Sugerencias EN VIVO de la plataforma para este mismo texto,
        // ya ordenadas por seguidores en el servidor. Sin duplicar con
        // los locales; en modo Favoritos solo entran las que tienen like.
        if (g_sugg_for == q)
            for (size_t i = 0; i < g_sugg_rows.size(); i++) {
                const Row &sr = g_sugg_rows[i];
                if (shown.count(sr.slug)) continue;
                if (g_favs_mode && !g_likes.count(sr.slug)) continue;
                g_view.push_back(sr);
                shown.insert(sr.slug);
                sugg_added++;
            }
    }
    if (!q.empty()) {
        // 0.7: con texto buscado, la lista va en orden alfabetico
        // (insensible a mayusculas); sin filtro se mantiene el orden
        // por espectadores de la API.
        std::sort(g_view.begin(), g_view.end(),
                  [](const Row &a, const Row &b) {
                      std::string la = lower_of(a.user);
                      std::string lb = lower_of(b.user);
                      if (la != lb) return la < lb;
                      return a.slug < b.slug;
                  });
    }
    g_table->rows((int)g_view.size());
    if (!g_view.empty()) g_table->select_row(0);
    g_table->redraw();
    if (announce && g_player_pid <= 0) {
        char m[224];
        if (!q.empty()) {
            if (sugg_added > 0)
                snprintf(m, sizeof(m),
                         "Filtro local: %zu de %zu directos y %zu "
                         "sugeridos en vivo para \xc2\xab%s\xc2\xbb.",
                         g_view.size() - sugg_added, base.size(),
                         sugg_added, typed.c_str());
            else
                snprintf(m, sizeof(m),
                         "Filtro local: %zu de %zu directos para \xc2\xab%s\xc2\xbb.",
                         g_view.size(), base.size(), typed.c_str());
            set_status(m);
        } else if (g_has_filter) {
            snprintf(m, sizeof(m),
                     "Filtro quitado: %zu directos en vivo.", g_rows.size());
            set_status(m);
        }
    }
    g_has_filter = !q.empty();
}

// El Enter NO se decide en el callback de texto: con FL_WHEN_CHANGED el
// event_key() no discrimina de forma fiable y el Enter se lo tragaba
// FLTK (bug firmado: el usuario se quedaba en «Filtro local: 0 de N»
// aunque el canal estuviera en vivo, p. ej. locosporlinux a las 18:16
// CDT con 19 espectadores por api/v2). SearchInput caza el FL_KEYDOWN
// antes de que la tecla se pierda y llama a do_search() directamente.
static void do_search();
class SearchInput : public Fl_Input {
public:
    SearchInput(int X, int Y, int W, int H) : Fl_Input(X, Y, W, H) {}
    int handle(int e) override {
        if (e == FL_KEYDOWN) {
            int k = Fl::event_key();
            if (k == FL_Enter || k == FL_KP_Enter) {
                do_search();
                return 1;
            }
        }
        return Fl_Input::handle(e);
    }
};

static void input_changed_cb(Fl_Widget *, void *) {
    apply_filter(true);
    // Debounce de sugerencias EN VIVO: watch_cb dispara JOB_SUGGEST a
    // los ~0,5 s del ultimo tecleo (>= 2 caracteres). Con menos, o al
    // borrar, las sugerencias se retiran.
    std::string q = lower_of(trim(g_input->value()));
    if (q.size() >= 2) {
        g_sugg_queued = q;
        g_last_key_t = now_s();
    } else {
        g_sugg_queued.clear();
        g_sugg_for.clear();
        g_sugg_rows.clear();
    }
}

static void quality_cb(Fl_Widget *, void *) {
    const int NQ = (int)(sizeof(QUALITIES) / sizeof(QUALITIES[0]));
    int idx = 0;
    for (int i = 0; i < NQ; i++) if (QUALITIES[i] == g_quality) idx = i;
    g_quality = QUALITIES[(idx + 1) % NQ];
    static char buf[32];
    snprintf(buf, sizeof(buf), "Calidad: %dp", g_quality);
    g_btn_quality->label(buf);
    cfg_save();
    char m[96];
    snprintf(m, sizeof(m), "Calidad fijada en %dp (se aplica al reproducir).",
             g_quality);
    set_status(m);
}

// ---------------------------------------------------------------- tema UI
static void apply_theme() {
    const Palette &P = pal();
    g_win->color(P.win);
    g_lbl_search->labelcolor(P.txt);
    g_lbl_head->labelcolor(P.txt);
    g_lbl_player->labelcolor(P.txt);
    g_status->labelcolor(P.txt);
    g_version->labelcolor(P.txt);
    g_input->color(P.input_bg);
    g_input->textcolor(P.txt);
    g_input->cursor_color(P.txt);
    g_input->selection_color(P.sel);
    Fl_Button *btns[] = {g_btn_search, g_btn_list, g_btn_theme,
                         g_btn_quality, g_btn_stop, g_btn_info,
                         g_btn_vod};
    for (int i = 0; i < 7; i++) {
        btns[i]->color(P.btn);
        btns[i]->labelcolor(P.txt);
        btns[i]->box(FL_BORDER_BOX);
    }
    update_favs_btn();
    g_btn_play->color(kick_green());
    g_btn_play->labelcolor(fl_rgb_color(10, 30, 5));
    g_btn_theme->label(g_dark ? "Modo claro" : "Modo oscuro");
    g_table->color(P.win);
    if (g_vod_win) {
        g_vod_win->color(P.win);
        g_vod_browser->color(P.input_bg);
        g_vod_browser->textcolor(P.txt);
        g_vod_status->labelcolor(P.txt);
        g_vod_win->redraw();
    }
    g_win->redraw();
    g_table->redraw();
}

static void theme_cb(Fl_Widget *, void *) {
    g_dark = !g_dark;
    cfg_save();
    apply_theme();
    set_status(g_dark ? "Modo oscuro activado." : "Modo claro activado.");
}

static void awake_cb(void *p) {
    JobResult *res = (JobResult *)p;
    if (res->kind != JOB_SUGGEST) busy(false);
    if (res->kind == JOB_SUGGEST) {
        // Silencioso: solo vale si responde al texto que sigue escrito.
        g_sugg_inflight.clear();
        if (res->ok && res->query == lower_of(trim(g_input->value()))) {
            g_sugg_rows = res->rows;
            g_sugg_for = res->query;
            apply_filter(true);  // anuncia «… y N sugeridos en vivo»
        }
        delete res;
        return;
    }
    if (res->kind == JOB_VOD_LIST) {
        if (res->ok) {
            if (res->query == g_vod_channel) {
                g_vods = res->vods;
                vod_refresh_ui();
                char msg[160];
                snprintf(msg, sizeof(msg),
                         "%zu grabaciones disponibles de %s.",
                         g_vods.size(), g_vod_channel.c_str());
                set_status(msg);
            }
        } else {
            if (g_vod_status)
                g_vod_status->copy_label(res->err.c_str());
            set_status(res->err);
        }
        delete res;
        return;
    }
    if (res->kind == JOB_VOD_PLAY) {
        if (res->ok)
            player_launch_vod(res->play_url, res->play_label);
        else {
            logo_spin_stop();
            set_status(res->err);
        }
        delete res;
        return;
    }
    if (res->kind == JOB_PLAY) {
        if (res->ok)
            player_launch(res->play_url, res->play_label, res->via_master);
        else {
            logo_spin_stop();  // 0.7: no hubo video, quita el efecto
            set_status(res->err);
        }
        delete res;
        return;
    }
    if (res->ok) {
        g_rows = res->rows;
        apply_filter(false);   // respeta el texto que haya en el buscador
        if (!res->note.empty()) set_status(res->note);
        else if (g_rows.empty()) set_status("Sin directos que mostrar.");
    } else {
        if (res->kind == JOB_CHANNEL && !res->note.empty()) {
            // canal existe pero fuera de directo: note trae el usuario
            set_status(std::string("\xc2\xab") + res->note +
                       "\xc2\xbb no esta en directo ahora.");
        } else if (res->kind == JOB_CHANNEL && res->notfound) {
            // 404: intentar como categoria
            std::string q = trim(g_input->value());
            delete res;
            run_job(JOB_CATEGORY, q, "Buscando como categoria...");
            return;
        } else {
            set_status(res->err);
        }
    }
    delete res;
}

// ---------------------------------------------------------------- grabaciones
static void vod_update_favorite() {
    if (!g_vod_favorite) return;
    bool saved = g_likes.count(g_vod_channel) != 0;
    g_vod_favorite->copy_label(
        saved ? "Quitar favorito" : "Agregar favorito");
    g_vod_favorite->redraw();
}

static void vod_favorite_cb(Fl_Widget *, void *) {
    if (g_vod_channel.empty()) return;

    if (g_likes.count(g_vod_channel))
        g_likes.erase(g_vod_channel);
    else
        g_likes.insert(g_vod_channel);

    cfg_save();
    vod_update_favorite();

    if (g_favs_mode) apply_filter(false);

    set_status(
        (g_likes.count(g_vod_channel)
            ? "Canal agregado a Favoritos: "
            : "Canal quitado de Favoritos: ") +
        g_vod_channel);
}

static void vod_refresh_ui() {
    if (!g_vod_browser || !g_vod_status) return;
    g_vod_browser->clear();
    for (size_t i = 0; i < g_vods.size(); ++i) {
        const Vod &v = g_vods[i];
        long secs = v.duration_ms / 1000;
        long hh = secs / 3600;
        long mm = (secs / 60) % 60;
        char prefix[100];
        snprintf(prefix, sizeof(prefix),
                 "%s  |  %ld:%02ld h  |  ",
                 v.date.substr(0, 10).c_str(), hh, mm);
        std::string title = v.title;
        for (size_t j = 0; j < title.size(); ++j)
            if (title[j] == '\n' || title[j] == '\r'
                || title[j] == '\t') title[j] = ' ';
        g_vod_browser->add((std::string(prefix) + title).c_str());
    }
    if (!g_vods.empty()) g_vod_browser->value(1);
    char msg[120];
    snprintf(msg, sizeof(msg), "%zu grabaciones de %s",
             g_vods.size(), g_vod_channel.c_str());
    g_vod_status->copy_label(msg);
}

static void vod_play_cb(Fl_Widget *, void *) {
    if (!g_vod_browser) return;
    int i = g_vod_browser->value() - 1;
    if (i < 0 || i >= (int)g_vods.size()) {
        set_status("Selecciona primero una grabacion.");
        return;
    }
    std::string source = g_vods[i].source;
    g_vod_win->hide();
    logo_spin_start();
    run_job(JOB_VOD_PLAY, source, "Preparando grabacion...");
}

static void vod_close_cb(Fl_Widget *, void *) {
    if (g_vod_win) g_vod_win->hide();
}

static void vod_cb(Fl_Widget *, void *) {
    if (g_player_pid > 0) {
        set_status("Detene primero el reproductor.");
        return;
    }
    std::string slug = slugify(trim(g_input->value()));
    if (slug.empty()) {
        int row = selected_row();
        if (row >= 0 && row < (int)g_view.size())
            slug = g_view[row].slug;
    }
    if (slug.empty()) {
        set_status("Escribi un canal o selecciona uno de la tabla.");
        return;
    }
    if (!g_vod_win) {
        g_vod_win = new Fl_Window(780, 460, "Grabaciones de Kick");
        g_vod_browser = new Fl_Browser(12, 15, 756, 365);
        g_vod_browser->type(FL_HOLD_BROWSER);
        g_vod_browser->textsize(13);
        g_vod_status = new Fl_Box(12, 388, 756, 24, "");
        g_vod_status->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE);
        Fl_Button *play = new Fl_Button(12, 418, 230, 32,
                                      "REPRODUCIR GRABACION");
        play->callback(vod_play_cb);
        g_vod_favorite = new Fl_Button(
            265, 418, 210, 32, "Agregar favorito");
        g_vod_favorite->callback(vod_favorite_cb);

        Fl_Button *close = new Fl_Button(620, 418, 148, 32,
                                       "Cerrar");
        close->callback(vod_close_cb);
        g_vod_win->end();
        g_vod_win->callback(vod_close_cb);
    }
    g_vod_channel = slug;
    vod_update_favorite();
    g_vods.clear();
    g_vod_browser->clear();
    g_vod_status->copy_label("Cargando grabaciones...");
    g_vod_win->show();
    apply_theme();
    run_job(JOB_VOD_LIST, slug, "Consultando grabaciones de Kick...");
}
// ---------------------------------------------------------------- ayuda
// Ventana «Ayuda de FLKicker» (estilo FLTube, aprobada por Juanca en
// maqueta v4): cabecera con la K, tres pestanas como botones (activa
// en el verde del logo 117,224,32 con etiqueta oscura; las inactivas
// del color del cuadro de texto, para fundirse con el) y pie con el
// aviso de cliente no oficial. Sin apartado de Atajos. Se repinta con
// la paleta actual de la app: si FLKicker esta en modo claro, la ayuda
// sale en claro (y al reves), llamando a help_theme() al abrir.
static Fl_Window *g_help_win = nullptr;
static Fl_Button *g_help_tabs[3];
static Fl_Group *g_help_pages[3];
static Fl_Text_Display *g_help_txt[3];
static Fl_Box *g_help_tocolor[16];  // etiquetas que siguen a P.txt
static Fl_Box *g_help_dim[4];       // etiquetas atenuadas (version, etc.)
static Fl_Box *g_help_url = nullptr;

static Fl_Color logo_green() { return fl_rgb_color(117, 224, 32); }
static Fl_Color dim_color() {
    return g_dark ? fl_rgb_color(148, 154, 166) : fl_rgb_color(105, 105, 105);
}

static void help_tab_cb(Fl_Widget *, void *v) {
    const Palette &P = pal();
    int sel = (int)(long)v;
    for (int i = 0; i < 3; i++) {
        if (i == sel) {
            g_help_tabs[i]->color(logo_green());
            g_help_tabs[i]->labelcolor(fl_rgb_color(10, 30, 5));
            g_help_pages[i]->show();
        } else {
            g_help_tabs[i]->color(P.input_bg);
            g_help_tabs[i]->labelcolor(P.txt);
            g_help_pages[i]->hide();
        }
        g_help_tabs[i]->redraw();
    }
}

static void help_theme() {
    const Palette &P = pal();
    g_help_win->color(P.win);
    int sel = 0;
    for (int i = 0; i < 3; i++) {
        g_help_pages[i]->color(P.win);
        g_help_txt[i]->color(P.input_bg);
        g_help_txt[i]->textcolor(P.txt);
        if (g_help_pages[i]->visible()) sel = i;
    }
    help_tab_cb(nullptr, (void *)(long)sel);
    for (int i = 0; g_help_tocolor[i]; i++)
        g_help_tocolor[i]->labelcolor(P.txt);
    for (int i = 0; g_help_dim[i]; i++)
        g_help_dim[i]->labelcolor(dim_color());
    if (g_help_url)
        g_help_url->labelcolor(g_dark ? kick_green()
                                      : fl_rgb_color(25, 125, 0));
    g_help_win->redraw();
}

static Fl_Text_Display *help_mktxt(int x, int y, int w, int h,
                                   const char *txt) {
    Fl_Text_Display *d = new Fl_Text_Display(x, y, w, h);
    d->box(FL_DOWN_BOX);
    d->textfont(FL_HELVETICA);
    d->textsize(13);
    d->wrap_mode(Fl_Text_Display::WRAP_AT_BOUNDS, 0);
    Fl_Text_Buffer *b = new Fl_Text_Buffer();
    b->text(txt);
    d->buffer(b);
    return d;
}

static Fl_Box *help_box(int x, int y, int w, int h, const char *t,
                        Fl_Box **to_color, Fl_Box **dim) {
    Fl_Box *b = new Fl_Box(x, y, w, h, t);
    b->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE);
    b->labelsize(13);
    if (to_color) *to_color = b;
    if (dim) *dim = b;
    return b;
}

static void open_help() {
    if (!g_help_win) {
        int tc = 0, dm = 0;
        g_help_win = new Fl_Window(640, 560, "Ayuda de FLKicker");

        static Fl_Image *hlogo = nullptr;
        {
            static const char *paths[] = {
                "icons/flkicker-128.png",
                "/usr/local/share/pixmaps/flkicker-128.png",
                "/usr/local/share/pixmaps/flkicker.png",
                "icons/flkicker-512.png",
                "icons/flkicker-48.png",
                "flkicker.png",
                nullptr,
            };
            for (int i = 0; paths[i] && !hlogo; i++) {
                Fl_PNG_Image *raw = new Fl_PNG_Image(paths[i]);
                if (raw->w() > 0 && raw->h() > 0)
                    hlogo = raw->copy(112, 112);
                delete raw;
            }
        }
        Fl_Box *blogo = new Fl_Box(18, 18, 112, 112);
        if (hlogo) blogo->image(hlogo);
        blogo->box(FL_NO_BOX);

        const int TX = 152;
        Fl_Box *name = help_box(TX, 14, 470, 34, "FLKicker",
                                &g_help_tocolor[tc++], nullptr);
        name->labelfont(FL_HELVETICA_BOLD);
        name->labelsize(26);
        help_box(TX, 54, 470, 20, "versión 0.7", nullptr,
                 &g_help_dim[dm++]);
        help_box(TX, 78, 470, 20,
                 "Mira directos de Kick en tu antiguo PC, sin cuenta.",
                 &g_help_tocolor[tc++], nullptr);
        help_box(TX, 106, 108, 20, "Tecnolog\xc3\xad" "as:",
                 &g_help_tocolor[tc++], nullptr);
        static const char *techs[] = {"FLTK", "curl", "ffmpeg/MPV",
                                      "C++", nullptr};
        static const int techx[] = {272, 340, 402, 552};
        for (int i = 0; techs[i]; i++)
            help_box(techx[i], 106, 90, 20, techs[i],
                     &g_help_tocolor[tc++], nullptr);
        help_box(TX, 130, 118, 20, "C\xc3\xb3" "digo fuente:",
                 &g_help_tocolor[tc++], nullptr);
        Fl_Box *url = help_box(272, 130, 340, 20,
                               "github.com/jcarlosrf26/flkicker",
                               nullptr, nullptr);
        url->labelfont(FL_HELVETICA_BOLD);
        url->labelcolor(kick_green());
        g_help_url = url;
        help_box(TX, 154, 470, 20, "Licenciado bajo GNU GPL v3.0", nullptr,
                 &g_help_dim[dm++]);
        g_help_tocolor[tc] = nullptr;
        g_help_dim[dm] = nullptr;

        static const char *tabnames[3] = {
            "C\xc3\xb3mo se usa", "Configuraci\xc3\xb3n", "Autores"};
        static const int tabx[3] = {10, 198, 386};
        static const int tabw[3] = {180, 180, 140};
        for (int i = 0; i < 3; i++) {
            Fl_Button *b = new Fl_Button(tabx[i], 186, tabw[i], 32,
                                         tabnames[i]);
            b->align(FL_ALIGN_CENTER | FL_ALIGN_INSIDE);
            b->box(FL_UP_BOX);
            b->labelfont(FL_HELVETICA_BOLD);
            b->labelsize(13);
            b->callback(help_tab_cb, (void *)(long)i);
            g_help_tabs[i] = b;
        }

        static const char *txts[3] = {
            "FLKicker es una aplicaci\xc3\xb3n para ver directos de "
            "Kick sin cuenta. Muestra primero los directos con m\xc3\xa1s "
            "espectadores y, al escribir en \xc2\xab" "Canal o "
            "categor\xc3\xad" "a\xc2\xbb, filtra esa lista al momento.\n"
            "\n"
            "Mientras escribes, FLKicker tambi\xc3\xa9n busca canales en "
            "directo en toda la plataforma y te los sugiere en la misma "
            "lista. Da Enter (o \xc2\xab" "Buscar\xc2\xbb) para comprobar "
            "un canal concreto: si est\xc3\xa1 en directo aparece su "
            "fila con punto verde; si est\xc3\xa1 apagado aparece con "
            "punto rojo (se puede marcar como favorito).\n"
            "\n"
            "Pulsa \xc2\xabREPRODUCIR\xc2\xbb (o doble clic sobre la "
            "fila) para abrir el v\xc3\xad" "deo. La calidad va de 160p a "
            "720p, con 360p por defecto.\n"
            "\n"
            "Pulsa el pulgar de un canal para marcarlo como favorito: "
            "queda guardado, y en \xc2\xab" "Favoritos\xc2\xbb la lista se "
            "filtra a tus canales con like que est\xc3\xa1n en directo.",
            "La configuraci\xc3\xb3n se guarda sola en ~/.flkickerrc: el "
            "modo oscuro o claro, la calidad por defecto (360p) y tus "
            "favoritos (los likes).\n"
            "\n"
            "Todo sobrevive a cerrar la aplicaci\xc3\xb3n y a reiniciar "
            "el equipo.\n"
            "\n"
            "Sin cuentas ni cookies: FLKicker no guarda credenciales de "
            "Kick; todo funciona de forma an\xc3\xb3nima, estilo "
            "FreeTube.",
            "FLKicker \xc2\xa9 Juan Carlos\n"
            "C\xc3\xb3" "digo fuente: github.com/jcarlosrf26/flkicker\n"
            "\n"
            "Proyectos que inspiraron FLKicker: FLTube, de Facundo "
            "Adorno; FLTV, de AnddyCort; y FLinux, de Nicol\xc3\xa1s "
            "Longardi, creador de FLinux.\n"
            "\n"
            "Cr\xc3\xa9" "ditos: a la comunidad FLTK y a Tiny Core "
            "Linux.\n"
            "\n"
            "Cliente no oficial, sin afiliaci\xc3\xb3n con Kick.\n"
            "\n"
            "Licenciado bajo GNU GPL v3.0."};
        for (int i = 0; i < 3; i++) {
            g_help_pages[i] = new Fl_Group(10, 218, 620, 264, "");
            g_help_txt[i] = help_mktxt(20, 228, 600, 244, txts[i]);
            g_help_pages[i]->end();
        }
        g_help_pages[1]->hide();
        g_help_pages[2]->hide();

        help_box(14, 524, 470, 20,
                 "Cliente no oficial, sin afiliaci\xc3\xb3n con Kick.",
                 nullptr, &g_help_dim[2]);
        g_help_dim[3] = nullptr;
        Fl_Box *gpl = new Fl_Box(500, 524, 126, 20, "GPL-3.0");
        gpl->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE);
        gpl->labelsize(12);
        gpl->labelcolor(dim_color());

        g_help_win->end();
    }
    help_theme();
    g_help_win->show();
}

static void info_cb(Fl_Widget *, void *) { open_help(); }

// ---------------------------------------------------------------- main
int main(int argc, char **argv) {
    (void)argc; (void)argv;
    cfg_load();
    curl_global_init(CURL_GLOBAL_DEFAULT);
    Fl::lock();
    Fl::scheme("gtk+");

    g_win = new Fl_Window(920, 600, "FLKicker - Kick en vivo");
    g_win->color(pal().win);

    // Logo K de FLKicker en la esquina superior izquierda, como marca
    // junto a la fila del buscador. Se carga el PNG del paquete
    // (flkicker-48.png instalado en pixmaps); ruta de reserva para
    // ejecutar desde el arbol de desarrollo. Es el mismo PNG en modo
    // oscuro y claro.
    static Fl_Image *s_logo = nullptr;
    {
        static const char *paths[] = {
            "/usr/local/share/pixmaps/flkicker.png",
            "icons/flkicker-48.png",
            "flkicker.png",
            nullptr,
        };
        for (int i = 0; paths[i] && !s_logo; i++) {
            Fl_PNG_Image *raw = new Fl_PNG_Image(paths[i]);
            if (raw->w() > 0 && raw->h() > 0)
                s_logo = raw->copy(42, 42);
            delete raw;
        }
        Fl_Box *logo = g_logo = new LogoBox(10, 4, 44, 44);
        if (s_logo) logo->image(s_logo);
        logo->box(FL_NO_BOX);
    }

    // 0.7: etiqueta estatica «Canal o categoría» junto al buscador.
    g_lbl_search = new Fl_Box(60, 12, 130, 26, "Canal o categoría:");
    g_lbl_search->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE);
    g_lbl_search->labelsize(13);

    g_input = new SearchInput(195, 12, 305, 26);
    g_input->textsize(13);
    g_input->when(FL_WHEN_CHANGED | FL_WHEN_ENTER_KEY);
    g_input->callback(input_changed_cb);
    g_input->tooltip("Escribe y la tabla se filtra al momento y te "
                     "sugiere canales en directo; Enter comprueba el "
                     "canal en Kick.");

    g_btn_info = new Fl_Button(862, 12, 48, 26, "i");
    g_btn_info->align(FL_ALIGN_CENTER | FL_ALIGN_INSIDE);
    g_btn_info->labelfont(FL_HELVETICA_BOLD | FL_ITALIC);
    g_btn_info->labelsize(16);
    g_btn_info->callback(info_cb);
    g_btn_info->tooltip("Ayuda de FLKicker");

    g_btn_search = new Fl_Button(505, 12, 100, 26, "Buscar");
    g_btn_search->align(FL_ALIGN_CENTER | FL_ALIGN_INSIDE);
    g_btn_search->callback(search_cb);
    g_btn_list = new Fl_Button(613, 12, 120, 26, "Directos");
    g_btn_list->align(FL_ALIGN_CENTER | FL_ALIGN_INSIDE);
    g_btn_list->callback(list_cb);
    g_btn_favs = new Fl_Button(741, 12, 120, 26, "Favoritos");
    g_btn_favs->align(FL_ALIGN_CENTER | FL_ALIGN_INSIDE);
    g_btn_favs->callback(favs_cb);

    g_lbl_head = new Fl_Box(10, 48, 480, 24,
                            "En vivo ahora - sin cuenta (via anonima)");
    g_lbl_head->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE);
    g_lbl_head->labelfont(FL_HELVETICA_BOLD);
    g_lbl_head->labelsize(13);

    g_btn_theme = new Fl_Button(700, 48, 210, 26, "Modo claro");
    g_btn_theme->align(FL_ALIGN_CENTER | FL_ALIGN_INSIDE);
    g_btn_theme->callback(theme_cb);

    g_table = new KickTable(10, 80, 900, 418);
    g_table->col_width(0, 182);
    g_table->col_width(1, 352);
    g_table->col_width(2, 84);
    g_table->col_width(3, 168);
    g_table->col_width(4, 84);
    g_table->row_height_all(26);
    g_table->col_header_height(26);
    g_table->callback(table_cb);
    g_table->when(FL_WHEN_RELEASE);

    g_btn_play = new Fl_Button(10, 510, 250, 40, "REPRODUCIR");
    g_btn_play->align(FL_ALIGN_CENTER | FL_ALIGN_INSIDE);
    g_btn_play->labelfont(FL_HELVETICA_BOLD);
    g_btn_play->labelsize(15);
    g_btn_play->color(kick_green());
    g_btn_play->callback(play_cb);

    g_btn_quality = new Fl_Button(272, 510, 140, 40);
    g_btn_quality->align(FL_ALIGN_CENTER | FL_ALIGN_INSIDE);
    {
        static char qb[32];
        snprintf(qb, sizeof(qb), "Calidad: %dp", g_quality);
        g_btn_quality->label(qb);
    }
    g_btn_quality->callback(quality_cb);

    g_btn_stop = new Fl_Button(424, 510, 130, 40, "Detener");
    g_btn_stop->align(FL_ALIGN_CENTER | FL_ALIGN_INSIDE);
    g_btn_stop->callback(stop_cb);

    g_btn_vod = new Fl_Button(566, 510, 160, 40, "Grabaciones");
    g_btn_vod->callback(vod_cb);
    g_btn_vod->tooltip("Ver videos archivados del canal");
    g_lbl_player = new Fl_Box(735, 518, 175, 24, "Reproductor: MPV");
    g_lbl_player->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE);
    g_lbl_player->labelsize(12);

    g_status = new Fl_Box(10, 566, 690, 22,
                          "Listo - via anonima estilo FreeTube - sin cuenta de Kick");
    g_status->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE);
    g_status->labelsize(12);

    g_version = new Fl_Box(710, 566, 200, 22, "FLKicker 0.7 - FLTK - C++");
    g_version->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE);
    g_version->labelsize(12);

    g_win->resizable(g_table);
    g_win->end();
    apply_theme();
    g_win->show();

    Fl::add_timeout(0.5, watch_cb);
    do_list();
    return Fl::run();
}
