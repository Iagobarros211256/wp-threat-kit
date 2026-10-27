// wphunter — scanner defensivo de IOC para árvores de arquivos WordPress.
//
// Aplica o checklist de caça a comprometimento aprendido no caso "CMSsmap":
//   - pastas de "plugin" com nome aleatório, poucos arquivos e sem readme;
//   - código PHP perigoso em arquivos de QUALQUER extensão (inclusive .db/.ico/.jpg);
//   - include/require de arquivos com extensão não-php;
//   - arquivos .php dentro de uploads/ ou na raiz;
//   - hashes exatos de artefatos conhecidos.
//
// É só leitura: nunca modifica, move ou executa nada do alvo.
//
//	go build -o wphunter ./cmd/wphunter
//	./wphunter -path /caminho/para/public_html
//	./wphunter -path . -json > achados.json
package main

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

type Severity string

const (
	Critical Severity = "CRITICAL"
	High     Severity = "HIGH"
	Medium   Severity = "MEDIUM"
	Low      Severity = "LOW"
)

type Finding struct {
	Severity Severity `json:"severity"`
	Rule     string   `json:"rule"`
	Path     string   `json:"path"`
	Detail   string   `json:"detail"`
}

// Hashes conhecidos da família CMSsmap. Chave = md5 OU sha256.
var knownHashes = map[string]string{
	"6f2394f0f643a1395159eec20976dbc6": "CMSsmap loader (index.php)",
	"8423d04c87e7d93c0aba4bce25fd3131": "CMSsmap payload (log.db)",
	"10cf2e3f52b5daee5ee47fb639a17003f019a3d8f9d0c0fc8fdfbcc71ff88453": "CMSsmap loader (index.php)",
	"670b560e471eab21477eec0a2861c650892e5d21e79f589d94b644273b1457b2": "CMSsmap payload (log.db)",
}

// Tokens de execução/injeção perigosos em PHP.
var dangerTokens = []string{
	"eval(", "assert(", "base64_decode", "gzinflate", "gzuncompress",
	"str_rot13", "create_function", "shell_exec", "passthru(", "proc_open",
	"popen(", "system(", "move_uploaded_file", "preg_replace",
	"$_POST", "$_REQUEST", "$_GET", "$_COOKIE",
	// específicos desta família / de backdoors de admin:
	"create_admin_if_missing", "build_str", "wp_insert_user",
}

// include/require de extensão não-php (o truque do log.db).
var oddIncludeRe = regexp.MustCompile(`(?i)(include|require)(_once)?\s*\(?\s*['"][^'"]+\.(db|ico|jpg|jpeg|png|gif|cache|log|txt|data|bin)['"]`)

// nome de pasta "aleatório": só letras minúsculas, 6-9 chars, sem vogal-consoante pronunciável garantida.
var randomDirRe = regexp.MustCompile(`^[a-z]{6,9}$`)

// extensões que podem carregar PHP mesmo "disfarçadas".
var codeLikeExt = map[string]bool{
	".php": true, ".phtml": true, ".php5": true, ".php7": true, ".inc": true,
	".db": true, ".ico": true, ".cache": true, ".log": true, ".data": true,
	".jpg": true, ".png": true, ".gif": true, ".txt": true,
}

const maxScanBytes = 2 << 20 // 2 MiB: lê só o começo de arquivos grandes

type scanner struct {
	root     string
	findings []Finding
}

func (s *scanner) add(sev Severity, rule, path, detail string) {
	rel, err := filepath.Rel(s.root, path)
	if err != nil {
		rel = path
	}
	s.findings = append(s.findings, Finding{sev, rule, rel, detail})
}

func main() {
	path := flag.String("path", ".", "diretório raiz a varrer (ex.: public_html)")
	asJSON := flag.Bool("json", false, "saída em JSON")
	flag.Parse()

	root, err := filepath.Abs(*path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "caminho inválido:", err)
		os.Exit(2)
	}
	s := &scanner{root: root}

	// 1) varredura estrutural de pastas de plugin.
	s.scanPluginDirs(root)

	// 2) varredura de conteúdo de arquivos.
	filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		s.scanFile(p, d)
		return nil
	})

	s.report(*asJSON)
}

// scanPluginDirs: sinaliza diretórios filhos de .../plugins/ com cara de dropper.
func (s *scanner) scanPluginDirs(root string) {
	filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		if filepath.Base(filepath.Dir(p)) != "plugins" {
			return nil
		}
		name := filepath.Base(p)
		entries, err := os.ReadDir(p)
		if err != nil {
			return nil
		}
		hasReadme, nFiles := false, 0
		for _, e := range entries {
			if !e.IsDir() {
				nFiles++
			}
			ln := strings.ToLower(e.Name())
			if strings.HasPrefix(ln, "readme") {
				hasReadme = true
			}
		}
		randomName := randomDirRe.MatchString(name)
		switch {
		case randomName && !hasReadme && nFiles <= 3:
			s.add(Critical, "suspicious-plugin-dir", p,
				fmt.Sprintf("nome aleatório, %d arquivo(s), sem readme — padrão de dropper", nFiles))
		case randomName && !hasReadme:
			s.add(High, "suspicious-plugin-dir", p, "nome aleatório e sem readme.txt")
		case !hasReadme && nFiles <= 2:
			s.add(Medium, "suspicious-plugin-dir", p,
				fmt.Sprintf("plugin sem readme e com só %d arquivo(s)", nFiles))
		}
		return nil
	})
}

func (s *scanner) scanFile(p string, d os.DirEntry) {
	ext := strings.ToLower(filepath.Ext(p))
	rel, _ := filepath.Rel(s.root, p)
	relSlash := filepath.ToSlash(rel)

	// hash de qualquer arquivo até um tamanho razoável.
	info, _ := d.Info()
	if info != nil && info.Size() < maxScanBytes {
		if desc, md5h, sha := s.hashCheck(p); desc != "" {
			s.add(Critical, "known-ioc-hash", p, fmt.Sprintf("%s [md5 %s]", desc, md5h[:12]))
			_ = sha
		}
	}

	// .php em uploads/ ou na raiz do webroot = quase sempre suspeito.
	if ext == ".php" {
		if strings.Contains(relSlash, "wp-content/uploads/") {
			s.add(High, "php-in-uploads", p, "arquivo .php dentro de uploads/")
		} else if !strings.Contains(relSlash, "/") && isWPRootStray(filepath.Base(p)) {
			s.add(Medium, "php-at-webroot", p, "arquivo .php não-padrão na raiz do site")
		}
	}

	if !codeLikeExt[ext] {
		return
	}

	// lê o começo do arquivo e procura PHP + tokens perigosos / include estranho.
	content := readHead(p, maxScanBytes)
	if len(content) == 0 {
		return
	}
	lc := string(content)

	hasPHPOpen := strings.Contains(lc, "<?php") || strings.Contains(lc, "<?=")
	if !hasPHPOpen {
		return
	}

	// include/require de extensão não-php.
	if m := oddIncludeRe.FindString(lc); m != "" {
		s.add(Critical, "odd-extension-include", p, "inclui código de extensão não-php: "+clip(m, 60))
	}

	// PHP vivo escondido em arquivo NÃO-.php.
	if ext != ".php" && ext != ".phtml" && ext != ".inc" {
		for _, t := range dangerTokens {
			if strings.Contains(lc, t) {
				s.add(Critical, "php-hidden-in-nonphp", p,
					fmt.Sprintf("extensão %s com PHP perigoso (%s)", ext, t))
				break
			}
		}
	}

	// combinação de backdoor de admin (vale mesmo em .php).
	if strings.Contains(lc, "build_str") &&
		(strings.Contains(lc, "WP_User") || strings.Contains(lc, "set_role") || strings.Contains(lc, "create_admin")) {
		s.add(Critical, "rogue-admin-payload", p, "funções de criação de admin + build_str (família CMSsmap)")
	}

	// silenciadores clássicos juntos.
	if strings.Contains(lc, "error_reporting(0)") && strings.Contains(lc, "ignore_user_abort") {
		s.add(High, "silencer-combo", p, "error_reporting(0)+ignore_user_abort — típico de shell")
	}
}

func (s *scanner) hashCheck(p string) (desc, md5hex, shahex string) {
	f, err := os.Open(p)
	if err != nil {
		return "", "", ""
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxScanBytes))
	if err != nil {
		return "", "", ""
	}
	m := md5.Sum(data)
	sh := sha256.Sum256(data)
	md5hex = hex.EncodeToString(m[:])
	shahex = hex.EncodeToString(sh[:])
	if d, ok := knownHashes[md5hex]; ok {
		return d, md5hex, shahex
	}
	if d, ok := knownHashes[shahex]; ok {
		return d, md5hex, shahex
	}
	return "", md5hex, shahex
}

func readHead(p string, n int64) []byte {
	f, err := os.Open(p)
	if err != nil {
		return nil
	}
	defer f.Close()
	b, _ := io.ReadAll(io.LimitReader(f, n))
	return b
}

// isWPRootStray: true se o nome NÃO é um arquivo padrão do core na raiz.
func isWPRootStray(name string) bool {
	std := map[string]bool{
		"index.php": true, "wp-activate.php": true, "wp-blog-header.php": true,
		"wp-comments-post.php": true, "wp-config.php": true, "wp-config-sample.php": true,
		"wp-cron.php": true, "wp-links-opml.php": true, "wp-load.php": true,
		"wp-login.php": true, "wp-mail.php": true, "wp-settings.php": true,
		"wp-signup.php": true, "wp-trackback.php": true, "xmlrpc.php": true,
	}
	return !std[strings.ToLower(name)]
}

func clip(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

var sevRank = map[Severity]int{Critical: 0, High: 1, Medium: 2, Low: 3}

func (s *scanner) report(asJSON bool) {
	sort.SliceStable(s.findings, func(i, j int) bool {
		if sevRank[s.findings[i].Severity] != sevRank[s.findings[j].Severity] {
			return sevRank[s.findings[i].Severity] < sevRank[s.findings[j].Severity]
		}
		return s.findings[i].Path < s.findings[j].Path
	})

	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(struct {
			Root     string    `json:"root"`
			Count    int       `json:"count"`
			Findings []Finding `json:"findings"`
		}{s.root, len(s.findings), s.findings})
		return
	}

	counts := map[Severity]int{}
	for _, f := range s.findings {
		counts[f.Severity]++
	}
	fmt.Printf("wphunter — alvo: %s\n", s.root)
	fmt.Printf("achados: %d  (CRITICAL %d · HIGH %d · MEDIUM %d · LOW %d)\n\n",
		len(s.findings), counts[Critical], counts[High], counts[Medium], counts[Low])
	for _, f := range s.findings {
		fmt.Printf("  [%-8s] %-24s %s\n", f.Severity, f.Rule, f.Path)
		fmt.Printf("             └─ %s\n", f.Detail)
	}
	if len(s.findings) == 0 {
		fmt.Println("  nenhum IOC conhecido encontrado (não prova ausência de comprometimento).")
	}
	if counts[Critical] > 0 {
		os.Exit(1) // útil em CI/pipeline
	}
}
