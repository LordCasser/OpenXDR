package hostimport

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func zippedDocument(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	for name, text := range files {
		f, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.Write([]byte(text)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
func TestExtractDocuments(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want []string
	}{
		{"notes.conf", []byte("主机 192.0.2.10，密码 a|b:c"), []string{"a|b:c"}},
		{"hosts.docx", zippedDocument(t, map[string]string{"word/document.xml": `<document><body><p><r><t>主机 192.0.2.10</t></r></p><p><r><t xml:space="preserve">密码 a&amp;b </t></r></p></body></document>`}), []string{"192.0.2.10", "密码 a&b "}},
		{"hosts.xlsx", zippedDocument(t, map[string]string{"xl/workbook.xml": `<workbook xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="生产组" sheetId="1" r:id="rId1"/></sheets></workbook>`, "xl/_rels/workbook.xml.rels": `<Relationships><Relationship Id="rId1" Target="worksheets/sheet1.xml"/></Relationships>`, "xl/sharedStrings.xml": `<sst><si><t>192.0.2.10</t></si><si><r><t>pass</t></r><r><t>word</t></r></si></sst>`, "xl/worksheets/sheet1.xml": `<worksheet><sheetData><row><c r="A1" t="s"><v>0</v></c><c r="C1" t="s"><v>1</v></c><c r="D1" t="inlineStr"><is><t>ops</t></is></c></row></sheetData></worksheet>`}), []string{"工作表 生产组", "A1: 192.0.2.10", "C1: password", "D1: ops"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			text, err := PrepareDocument(context.Background(), test.name, test.data)
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range test.want {
				if !strings.Contains(text.Text, want) {
					t.Fatalf("缺少字段 %q", want)
				}
			}
		})
	}
	for _, test := range []struct {
		name string
		data []byte
	}{{"legacy.doc", []byte{0xff, 0x00}}, {"bad.docx", []byte("not a zip")}, {"blank.txt", []byte("  ")}, {"large.txt", bytes.Repeat([]byte("a"), MaxDocument+1)}} {
		if _, err := PrepareDocument(context.Background(), test.name, test.data); err == nil {
			t.Fatal("接受无效文档", test.name)
		}
	}
}
func TestExtractPDF(t *testing.T) {
	if _, err := exec.LookPath("pdftoppm"); err != nil {
		t.Skip("本机未安装 poppler-utils")
	}
	var pdf bytes.Buffer
	pdf.WriteString("%PDF-1.4\n")
	offsets := []int{0}
	content := "BT /F1 16 Tf 50 700 Td (app-prod 192.0.2.10 ops) Tj ET"
	objects := []string{"<< /Type /Catalog /Pages 2 0 R >>", "<< /Type /Pages /Kids [3 0 R] /Count 1 >>", "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>", "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>", fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", len(content), content)}
	for i, obj := range objects {
		offsets = append(offsets, pdf.Len())
		fmt.Fprintf(&pdf, "%d 0 obj\n%s\nendobj\n", i+1, obj)
	}
	start := pdf.Len()
	fmt.Fprintf(&pdf, "xref\n0 %d\n0000000000 65535 f \n", len(offsets))
	for _, offset := range offsets[1:] {
		fmt.Fprintf(&pdf, "%010d 00000 n \n", offset)
	}
	fmt.Fprintf(&pdf, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(offsets), start)
	text, err := PrepareDocument(context.Background(), "hosts.pdf", pdf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if len(text.Images) != 1 || text.Text != "" {
		t.Fatal("PDF 内容缺失")
	}
}

func TestVisionDocuments(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "handoff.png"))
	if err != nil {
		t.Fatal(err)
	}
	original, err := documentImage("original", data)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"handoff.png", "with-image.docx"} {
		input := data
		if name == "with-image.docx" {
			input = zippedDocument(t, map[string]string{"word/document.xml": "<document><body><p><r><t>交接</t></r></p></body></document>", "word/media/image1.png": string(data)})
		}
		doc, err := PrepareDocument(context.Background(), name, input)
		if err != nil || len(doc.Images) != 1 || doc.Images[0].DataURL != original.DataURL {
			t.Fatalf("原图未保留: %v", err)
		}
	}
	if err := (Document{Images: []DocumentImage{{DataURL: "https://example.com/image.png"}}}).Validate(); err == nil {
		t.Fatal("接受远程 URL")
	}
	if _, err := exec.LookPath("pdftoppm"); err != nil {
		t.Skip("未安装 PDF 渲染组件")
	}
	data, err = os.ReadFile(filepath.Join("testdata", "handoff-scan.pdf"))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := PrepareDocument(context.Background(), "scan.pdf", data)
	if err != nil || len(doc.Images) != 1 || doc.Text != "" {
		t.Fatalf("扫描 PDF 未保留图像: %v", err)
	}
}
