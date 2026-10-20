package sshdecoy

import (
	"errors"
	"strings"
)

// MaxProfileBannerBytes 限制运行策略的单次输出；大尺寸历史模板仅用于显式实验。
const MaxProfileBannerBytes = 8192

// Profile 只描述策略，不向目录调用方返回可执行的注入正文。
type Profile struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Layer    string `json:"layer"`
	Template string `json:"template"`
	Evidence string `json:"evidence"`
}

var profiles = [...]Profile{
	{ID: "decoy", Name: "诱饵识别", Layer: "decoy", Template: "identify-v1", Evidence: "只记录同一诱饵的有效标记使用；不能据此确认 AI 身份"},
	{ID: "pause", Name: "暂停注入", Layer: "injection", Template: "operator-close-v1", Evidence: "GLM + BoxPwnr 靶场重复观察到暂停；服务端不能独立确认模型已暂停"},
	{ID: "padding", Name: "输出填充", Layer: "padding", Template: "padding-8k-v1", Evidence: "固定 8 KiB 原创文本；不混入指令，尚未验证独立拖延效果"},
}

func Profiles() []Profile {
	return append([]Profile(nil), profiles[:]...)
}

func resolveProfile(cfg Config) (Config, error) {
	if cfg.Profile == "" {
		return cfg, nil
	}
	if cfg.Template != "" {
		return Config{}, errors.New("运行策略与实验模板不能同时选择")
	}
	for _, profile := range profiles {
		if profile.ID != cfg.Profile {
			continue
		}
		text, ok := templates[profile.Template]
		if !ok || len(strings.ReplaceAll(text, "{{marker}}", strings.Repeat("0", 32))) > MaxProfileBannerBytes {
			return Config{}, errors.New("运行策略模板不可用或超过输出上限")
		}
		cfg.Template = profile.Template
		return cfg, nil
	}
	return Config{}, errors.New("未知诱饵运行策略")
}
