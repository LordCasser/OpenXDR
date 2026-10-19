package hostimport

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const MaxUpload = 20 << 20
const MaxPages = 30

// Document 保留文本和图像。图像直接发给视觉模型，不经过本地 OCR。
type Document struct {
	Text   string          `json:"document"`
	Images []DocumentImage `json:"images"`
}
type DocumentImage struct {
	Name    string `json:"name"`
	DataURL string `json:"dataUrl"`
}

func documentImage(name string, data []byte) (DocumentImage, error) {
	mime := http.DetectContentType(data)
	switch mime {
	case "image/png", "image/jpeg", "image/webp", "image/gif":
	default:
		return DocumentImage{}, errors.New("图片须为 PNG、JPEG、WebP 或 GIF")
	}
	return DocumentImage{Name: name, DataURL: "data:" + mime + ";base64," + base64.StdEncoding.EncodeToString(data)}, nil
}

// PrepareDocument 不执行宏、不跟随外部链接。PDF 只渲染页面，不识别文字。
func PrepareDocument(ctx context.Context, name string, data []byte) (Document, error) {
	if len(data) == 0 || len(data) > MaxUpload {
		return Document{}, errors.New("文件须非空，最大 20 MiB")
	}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	var doc Document
	var err error
	switch ext := strings.ToLower(filepath.Ext(name)); ext {
	case ".docx", ".xlsx":
		doc, err = extractOffice(ctx, data, ext)
	case ".pdf":
		doc, err = renderPDF(ctx, data)
	case ".png", ".jpg", ".jpeg", ".webp", ".gif":
		var img DocumentImage
		img, err = documentImage(name, data)
		doc.Images = []DocumentImage{img}
	default:
		if !utf8.Valid(data) || bytes.ContainsRune(data, 0) {
			return Document{}, errors.New("不支持该二进制文档，请转换为 PDF、DOCX、XLSX、图片或 UTF-8 文本")
		}
		doc.Text = strings.TrimPrefix(string(data), "\ufeff")
	}
	if err != nil {
		return Document{}, err
	}
	if err = doc.Validate(); err != nil {
		return Document{}, err
	}
	return doc, nil
}

// Validate 同时用于上传结果和分析请求，不接受远程图片 URL，避免服务端代取未知地址。
func (d Document) Validate() error {
	if len(d.Text) > MaxDocument || !utf8.ValidString(d.Text) {
		return errors.New("文字须为 UTF-8，最大 1 MiB")
	}
	if strings.TrimSpace(d.Text) == "" && len(d.Images) == 0 {
		return errors.New("请提供文档文字或图片")
	}
	if len(d.Images) > MaxPages {
		return errors.New("图片或 PDF 页数最多 30，请拆分后导入")
	}
	total := 0
	for _, img := range d.Images {
		prefix, payload, ok := strings.Cut(img.DataURL, ",")
		if !ok || len(payload) > base64.StdEncoding.EncodedLen(MaxUpload) {
			return errors.New("图片数据无效或过大")
		}
		data, err := base64.StdEncoding.DecodeString(payload)
		if err != nil {
			return errors.New("图片数据无效")
		}
		total += len(data)
		mime := http.DetectContentType(data)
		if prefix != "data:"+mime+";base64" {
			return errors.New("图片类型不匹配")
		}
		switch mime {
		case "image/png", "image/jpeg", "image/webp", "image/gif":
		default:
			return errors.New("不支持的图片类型")
		}
		if len(img.Name) > 512 || total > MaxUpload {
			return errors.New("图片总大小超过 20 MiB 或名称过长")
		}
	}
	return nil
}

func extractOffice(ctx context.Context, data []byte, ext string) (Document, error) {
	archive, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return Document{}, errors.New("Office 文档无效或已加密")
	}
	if len(archive.File) > 10000 {
		return Document{}, errors.New("Office 文档条目过多")
	}
	files := map[string]*zip.File{}
	for _, file := range archive.File {
		files[file.Name] = file
	}
	total := 0
	read := func(name string) ([]byte, error) {
		file := files[name]
		if file == nil {
			return nil, errors.New("Office 文档结构不完整")
		}
		if file.UncompressedSize64 > 8*MaxDocument {
			return nil, errors.New("Office 文档展开过大")
		}
		r, err := file.Open()
		if err != nil {
			return nil, errors.New("Office 文档无法读取")
		}
		defer r.Close()
		b, err := io.ReadAll(io.LimitReader(r, 8*MaxDocument+1))
		total += len(b)
		if err != nil || total > 32*MaxDocument || len(b) > 8*MaxDocument {
			return nil, errors.New("Office 文档展开过大或损坏")
		}
		return b, nil
	}
	if ext == ".docx" {
		b, err := read("word/document.xml")
		if err != nil {
			return Document{}, err
		}
		text, err := wordText(b)
		if err != nil {
			return Document{}, err
		}
		var extras []string
		for name := range files {
			if strings.HasPrefix(name, "word/header") || strings.HasPrefix(name, "word/footer") || name == "word/footnotes.xml" || name == "word/endnotes.xml" {
				if strings.HasSuffix(name, ".xml") {
					extras = append(extras, name)
				}
			}
		}
		sort.Strings(extras)
		for _, name := range extras {
			b, err := read(name)
			if err != nil {
				return Document{}, err
			}
			extra, err := wordText(b)
			if err != nil {
				return Document{}, err
			}
			text += "\n" + name + "\n" + extra
		}
		return appendOfficeImages(ctx, text, files, read)
	}
	var shared []string
	if files["xl/sharedStrings.xml"] != nil {
		b, err := read("xl/sharedStrings.xml")
		if err != nil {
			return Document{}, err
		}
		var table struct {
			Items []struct {
				Text string `xml:"t"`
				Runs []struct {
					Text string `xml:"t"`
				} `xml:"r"`
			} `xml:"si"`
		}
		if xml.Unmarshal(b, &table) != nil {
			return Document{}, errors.New("Excel 共享字符串无效")
		}
		for _, item := range table.Items {
			value := item.Text
			for _, r := range item.Runs {
				value += r.Text
			}
			shared = append(shared, value)
		}
	}
	sheetNames := map[string]string{}
	if files["xl/workbook.xml"] != nil && files["xl/_rels/workbook.xml.rels"] != nil {
		book, err := read("xl/workbook.xml")
		if err != nil {
			return Document{}, err
		}
		links, err := read("xl/_rels/workbook.xml.rels")
		if err != nil {
			return Document{}, err
		}
		var wb struct {
			Sheets []struct {
				Name string `xml:"name,attr"`
				ID   string `xml:"id,attr"`
			} `xml:"sheets>sheet"`
		}
		var rel struct {
			Items []struct {
				ID     string `xml:"Id,attr"`
				Target string `xml:"Target,attr"`
			} `xml:"Relationship"`
		}
		if xml.Unmarshal(book, &wb) != nil || xml.Unmarshal(links, &rel) != nil {
			return Document{}, errors.New("Excel 工作簿无效")
		}
		for _, sheet := range wb.Sheets {
			for _, link := range rel.Items {
				if sheet.ID == link.ID {
					target := strings.TrimPrefix(link.Target, "/")
					if !strings.HasPrefix(target, "xl/") {
						target = "xl/" + target
					}
					sheetNames[filepath.ToSlash(filepath.Clean(target))] = sheet.Name
				}
			}
		}
	}
	var names []string
	for name := range files {
		if strings.HasPrefix(name, "xl/worksheets/sheet") && strings.HasSuffix(name, ".xml") {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	if len(names) == 0 || len(names) > 100 {
		return Document{}, errors.New("Excel 工作表数量无效")
	}
	var out strings.Builder
	for _, name := range names {
		b, err := read(name)
		if err != nil {
			return Document{}, err
		}
		var sheet struct {
			Rows []struct {
				Cells []struct {
					Ref    string `xml:"r,attr"`
					Type   string `xml:"t,attr"`
					Value  string `xml:"v"`
					Inline struct {
						Text string `xml:"t"`
						Runs []struct {
							Text string `xml:"t"`
						} `xml:"r"`
					} `xml:"is"`
				} `xml:"c"`
			} `xml:"sheetData>row"`
		}
		if xml.Unmarshal(b, &sheet) != nil {
			return Document{}, errors.New("Excel 工作表无效")
		}
		label := sheetNames[name]
		if label == "" {
			label = name
		}
		fmt.Fprintf(&out, "\n工作表 %s\n", label)
		for _, row := range sheet.Rows {
			for _, cell := range row.Cells {
				value := cell.Value
				if cell.Type == "s" {
					n, err := strconv.Atoi(value)
					if err != nil || n < 0 || n >= len(shared) {
						return Document{}, errors.New("Excel 单元格引用无效")
					}
					value = shared[n]
				}
				if cell.Type == "inlineStr" {
					value = cell.Inline.Text
					for _, r := range cell.Inline.Runs {
						value += r.Text
					}
				}
				fmt.Fprintf(&out, "%s: %s\t", cell.Ref, value)
			}
			out.WriteByte('\n')
			if out.Len() > MaxDocument {
				return Document{}, errors.New("Excel 提取内容超过 1 MiB")
			}
		}
	}
	return appendOfficeImages(ctx, out.String(), files, read)
}

func appendOfficeImages(ctx context.Context, text string, files map[string]*zip.File, read func(string) ([]byte, error)) (Document, error) {
	var names []string
	for name := range files {
		if strings.HasPrefix(name, "word/media/") || strings.HasPrefix(name, "xl/media/") {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	if len(names) > MaxPages {
		return Document{}, errors.New("Office 图片超过 30 张，请拆分文档")
	}
	doc := Document{Text: text}
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return Document{}, errors.New("文档处理已取消")
		}
		data, err := read(name)
		if err != nil {
			return Document{}, err
		}
		img, err := documentImage(name, data)
		if err != nil {
			return Document{}, errors.New("Office 含不支持的图片，请转为 PDF 后导入")
		}
		doc.Images = append(doc.Images, img)
	}
	return doc, nil
}

func wordText(data []byte) (string, error) {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	var out strings.Builder
	inText := false
	for {
		tok, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", errors.New("Word 文档 XML 无效")
		}
		switch v := tok.(type) {
		case xml.StartElement:
			switch v.Name.Local {
			case "t":
				inText = true
			case "tab":
				out.WriteByte('\t')
			case "br":
				out.WriteByte('\n')
			}
		case xml.EndElement:
			switch v.Name.Local {
			case "t":
				inText = false
			case "p", "tr":
				out.WriteByte('\n')
			case "tc":
				out.WriteString("\t")
			}
		case xml.CharData:
			if inText {
				out.Write(v)
			}
		}
		if out.Len() > MaxDocument {
			return "", errors.New("Word 提取内容超过 1 MiB")
		}
	}
	return out.String(), nil
}

type boundedOutput struct{ bytes.Buffer }

func (b *boundedOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > MaxDocument {
		return 0, errors.New("输出过大")
	}
	return b.Buffer.Write(p)
}
func documentCommand(ctx context.Context, name string, args ...string) (string, error) {
	var out boundedOutput
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = &out
	if cmd.Run() != nil {
		return "", errors.New("文档转换失败或超时；请确认已安装 PDF 渲染组件，文档未加密且内容清晰")
	}
	return out.String(), nil
}
func renderPDF(ctx context.Context, data []byte) (Document, error) {
	dir, err := os.MkdirTemp("", "openxdr-document-")
	if err != nil {
		return Document{}, errors.New("无法创建文档转换目录")
	}
	defer os.RemoveAll(dir)
	source := filepath.Join(dir, "source.pdf")
	if os.WriteFile(source, data, 0600) != nil {
		return Document{}, errors.New("无法暂存文档")
	}
	info, err := documentCommand(ctx, "pdfinfo", source)
	if err != nil {
		return Document{}, err
	}
	pages := 0
	for _, line := range strings.Split(info, "\n") {
		if strings.HasPrefix(line, "Pages:") {
			pages, _ = strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "Pages:")))
		}
	}
	if pages < 1 || pages > MaxPages {
		return Document{}, errors.New("PDF 最多 30 页，请拆分后导入")
	}
	doc := Document{}
	total := 0
	for n := 1; n <= pages; n++ {
		page := strconv.Itoa(n)
		prefix := filepath.Join(dir, "page")
		if _, err := documentCommand(ctx, "pdftoppm", "-f", page, "-l", page, "-scale-to", "2200", "-singlefile", "-png", source, prefix); err != nil {
			return Document{}, err
		}
		f, err := os.Open(prefix + ".png")
		if err != nil {
			return Document{}, errors.New("无法读取 PDF 页面")
		}
		data, err := io.ReadAll(io.LimitReader(f, MaxUpload+1))
		f.Close()
		total += len(data)
		if err != nil || total > MaxUpload {
			return Document{}, errors.New("PDF 页面图像超过 20 MiB，请拆分文档")
		}
		img, err := documentImage("PDF 第 "+page+" 页", data)
		if err != nil {
			return Document{}, err
		}
		doc.Images = append(doc.Images, img)
	}
	return doc, nil
}
