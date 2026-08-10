package publicexperience

type Translations struct {
	PageTitle            string
	TrustLabel           string
	ReadyTitle           string
	Intro                string
	Loading              string
	ReadyMessage         string
	AvailableUntil       string
	AvailableUntilSuffix string
	PasswordLabel        string
	Show                 string
	Hide                 string
	Reveal               string
	Revealing            string
	SecurityNote         string
	WrongPassword        string
	RevealedTitle        string
	RevealedDescription  string
	OneTimeWarning       string
	Copy                 string
	CopyAll              string
	CopySuccess          string
	UnavailableTitle     string
	UnavailableMessage   string
	SessionLostTitle     string
	SessionLostMessage   string
	NetworkTitle         string
	NetworkMessage       string
	Retry                string
	InvalidDate          string
	PreviewLabel         string
	PreviewExpiration    string
	PreviewUsername      string
	PreviewAPIKey        string
}

type PageData struct {
	Locale               string
	Direction            string
	DateLocale           string
	PreviewExpirationISO string
	Text                 Translations
}

const previewExpirationISO = "2026-08-10T13:03:00Z"

var catalogs = map[string]Translations{
	LocaleEnglish: {
		PageTitle:            "Secure Secret",
		TrustLabel:           "SecureShare · One-time delivery",
		ReadyTitle:           "View confidential information",
		Intro:                "Please note that this information can only be viewed once. Before revealing it, make sure you are in a secure environment and save the information in a trusted location to avoid losing access to it.",
		Loading:              "Preparing secure link...",
		ReadyMessage:         "The information remains available until you choose “Reveal information”.",
		AvailableUntil:       "Available until",
		AvailableUntilSuffix: ".",
		PasswordLabel:        "Link password",
		Show:                 "Show",
		Hide:                 "Hide",
		Reveal:               "Reveal information",
		Revealing:            "Revealing information...",
		SecurityNote:         "Make sure you save the information. After it is revealed, leaving or refreshing this page will permanently remove your access to it.",
		WrongPassword:        "The link password is incorrect. Try again.",
		RevealedTitle:        "Confidential information revealed",
		RevealedDescription:  "Copy all of the information now and store it only in a secure location you trust.",
		OneTimeWarning:       "Once you leave or refresh this page, this information cannot be viewed again.",
		Copy:                 "Copy",
		CopyAll:              "Copy all information",
		CopySuccess:          "Copied",
		UnavailableTitle:     "This link is no longer available",
		UnavailableMessage:   "This link has expired, was revoked, or has already been viewed.",
		SessionLostTitle:     "Reopen the original secure link",
		SessionLostMessage:   "For your security, this link is not stored in the browser. Reopen the original link you received.",
		NetworkTitle:         "SecureShare could not be reached",
		NetworkMessage:       "The secure link remains available on this page. Check your connection and try again.",
		Retry:                "Try again",
		InvalidDate:          "Invalid date",
		PreviewLabel:         "Safe preview · fake data",
		PreviewExpiration:    "August 10, 2026 at 4:33 PM",
		PreviewUsername:      "Username",
		PreviewAPIKey:        "API key",
	},
	LocalePersian: {
		PageTitle:            "اطلاعات محرمانه",
		TrustLabel:           "SecureShare · ارسال یک‌بارمصرف",
		ReadyTitle:           "مشاهده اطلاعات محرمانه",
		Intro:                "توجه داشته باشید این اطلاعات فقط یک‌بار قابل نمایش است. پیش از اقدام برای مشاهده از امنیت محیط اطمینان حاصل کنید و حتما اطلاعات را برای پیشگیری از فراموشی در یک جای امن ذخیره کنید.",
		Loading:              "در حال آماده‌سازی لینک امن…",
		ReadyMessage:         "اطلاعات فقط تا پیش از انتخاب «نمایش اطلاعات» قابل مشاهده است.",
		AvailableUntil:       "قابل مشاهده تا",
		AvailableUntilSuffix: "",
		PasswordLabel:        "رمز لینک",
		Show:                 "نمایش",
		Hide:                 "مخفی‌کردن",
		Reveal:               "نمایش اطلاعات",
		Revealing:            "در حال نمایش…",
		SecurityNote:         "اطلاعات را حتما ذخیره کنید. پس از نمایش، یا خروج یا بارگذاری مجدد صفحه دیگر به آن دسترسی ندارید.",
		WrongPassword:        "رمز لینک صحیح نیست. دوباره تلاش کنید.",
		RevealedTitle:        "نمایش اطلاعات محرمانه",
		RevealedDescription:  "همه اطلاعات را همین حالا کپی و فقط در محل امن مورد تأیید خودتان حفظ و نگهداری کنید.",
		OneTimeWarning:       "پس از خروج از این صفحه یا بارگذاری مجدد آن، امکان مشاهده دوباره این اطلاعات وجود ندارد.",
		Copy:                 "کپی",
		CopyAll:              "کپی همه اطلاعات",
		CopySuccess:          "کپی شد",
		UnavailableTitle:     "این لینک دیگر در دسترس نیست",
		UnavailableMessage:   "این لینک منقضی شده، لغو شده یا قبلاً مشاهده شده است.",
		SessionLostTitle:     "برای ادامه، لینک اصلی را دوباره باز کنید",
		SessionLostMessage:   "برای حفظ امنیت، این لینک در مرورگر ذخیره نمی‌شود. لینک اصلی ارسال‌شده را دوباره باز کنید.",
		NetworkTitle:         "ارتباط با SecureShare برقرار نشد",
		NetworkMessage:       "لینک امن در همین صفحه باقی مانده است. اتصال شبکه را بررسی کنید و دوباره تلاش کنید.",
		Retry:                "تلاش دوباره",
		InvalidDate:          "تاریخ نامعتبر",
		PreviewLabel:         "پیش‌نمایش امن · اطلاعات آزمایشی",
		PreviewExpiration:    "۱۹ مرداد ۱۴۰۵، ساعت ۱۶:۳۳",
		PreviewUsername:      "نام کاربری",
		PreviewAPIKey:        "کلید API",
	},
}

func Catalog(locale string) PageData {
	locale = NormalizeLocale(locale)
	direction := "ltr"
	dateLocale := "en"
	if locale == LocalePersian {
		direction = "rtl"
		dateLocale = "fa-IR-u-ca-persian"
	}
	return PageData{Locale: locale, Direction: direction, DateLocale: dateLocale, PreviewExpirationISO: previewExpirationISO, Text: catalogs[locale]}
}
