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
	Locale     string
	Direction  string
	DateLocale string
	Text       Translations
}

var catalogs = map[string]Translations{
	LocaleEnglish: {
		PageTitle:            "Secure Secret",
		TrustLabel:           "SecureShare · One-time delivery",
		ReadyTitle:           "A secure secret has been shared with you",
		Intro:                "This secret can only be viewed once. Choose a private setting before revealing it.",
		Loading:              "Preparing secure link...",
		ReadyMessage:         "The link is ready. Opening this page has not consumed the secret.",
		AvailableUntil:       "Available until",
		AvailableUntilSuffix: ".",
		PasswordLabel:        "Link password",
		Show:                 "Show",
		Hide:                 "Hide",
		Reveal:               "Reveal secret",
		Revealing:            "Revealing...",
		SecurityNote:         "Only reveal this secret in a private setting. Leaving or refreshing the page after reveal will make it unavailable here.",
		WrongPassword:        "The link password is incorrect. Try again.",
		RevealedTitle:        "Secret revealed",
		RevealedDescription:  "After leaving or refreshing this page, this secret cannot be viewed again.",
		OneTimeWarning:       "Copy what you need now and keep it in an approved secure location.",
		Copy:                 "Copy",
		CopyAll:              "Copy all",
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
		PreviewExpiration:    "December 30, 2026 at 2:30 PM",
		PreviewUsername:      "Username",
		PreviewAPIKey:        "API key",
	},
	LocalePersian: {
		PageTitle:            "اطلاعات محرمانه",
		TrustLabel:           "SecureShare · ارسال یک‌بارمصرف",
		ReadyTitle:           "یک اطلاعات محرمانه برای شما ارسال شده است",
		Intro:                "این اطلاعات فقط یک‌بار قابل مشاهده است. لطفاً پیش از نمایش، در یک محیط امن و خصوصی قرار بگیرید.",
		Loading:              "در حال آماده‌سازی لینک امن...",
		ReadyMessage:         "لینک آماده نمایش است. باز کردن این صفحه باعث مصرف شدن اطلاعات نشده است.",
		AvailableUntil:       "قابل مشاهده تا",
		AvailableUntilSuffix: "",
		PasswordLabel:        "رمز لینک",
		Show:                 "نمایش",
		Hide:                 "مخفی کردن",
		Reveal:               "نمایش اطلاعات",
		Revealing:            "در حال نمایش...",
		SecurityNote:         "اطلاعات را فقط در محیطی امن و خصوصی نمایش دهید. پس از نمایش، با خروج یا بارگذاری مجدد صفحه دیگر به آن دسترسی نخواهید داشت.",
		WrongPassword:        "رمز لینک صحیح نیست. دوباره تلاش کنید.",
		RevealedTitle:        "اطلاعات محرمانه نمایش داده شد",
		RevealedDescription:  "پس از خروج از این صفحه یا بارگذاری مجدد آن، امکان مشاهده دوباره این اطلاعات وجود ندارد.",
		OneTimeWarning:       "اطلاعات موردنیاز را همین حالا کپی و فقط در محل امن مورد تأیید نگهداری کنید.",
		Copy:                 "کپی",
		CopyAll:              "کپی همه",
		CopySuccess:          "کپی شد",
		UnavailableTitle:     "این لینک دیگر در دسترس نیست",
		UnavailableMessage:   "این لینک منقضی شده، لغو شده یا قبلاً مشاهده شده است.",
		SessionLostTitle:     "برای ادامه، لینک اصلی را دوباره باز کنید",
		SessionLostMessage:   "برای حفظ امنیت، اطلاعات این لینک در مرورگر ذخیره نمی‌شود. لطفاً همان لینک اصلی که برای شما ارسال شده است را دوباره باز کنید.",
		NetworkTitle:         "ارتباط با SecureShare برقرار نشد",
		NetworkMessage:       "لینک امن در همین صفحه باقی مانده است. اتصال شبکه را بررسی و دوباره تلاش کنید.",
		Retry:                "تلاش دوباره",
		InvalidDate:          "تاریخ نامعتبر",
		PreviewLabel:         "پیش‌نمایش امن · اطلاعات آزمایشی",
		PreviewExpiration:    "۳۰ دسامبر ۲۰۲۶، ساعت ۱۴:۳۰",
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
		dateLocale = "fa-IR-u-ca-gregory"
	}
	return PageData{Locale: locale, Direction: direction, DateLocale: dateLocale, Text: catalogs[locale]}
}
