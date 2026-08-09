package publicexperience

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestServiceDefaultsToEnglishAndValidatesUpdates(t *testing.T) {
	service := NewService(NewMemoryStore())
	settings, err := service.Current(context.Background())
	if err != nil || settings.PublicLocale != LocaleEnglish {
		t.Fatalf("default settings = %+v err=%v", settings, err)
	}
	updated, err := service.Update(context.Background(), uuid.New(), " FA ")
	if err != nil || updated.PublicLocale != LocalePersian {
		t.Fatalf("Persian update = %+v err=%v", updated, err)
	}
	if _, err := service.Update(context.Background(), uuid.New(), "de"); !errors.Is(err, ErrInvalidLocale) {
		t.Fatalf("invalid locale err = %v", err)
	}
}

func TestCatalogProvidesSemanticDirectionAndCompletePersianCopy(t *testing.T) {
	english := Catalog(LocaleEnglish)
	if english.Locale != LocaleEnglish || english.Direction != "ltr" || english.Text.ReadyTitle == "" {
		t.Fatalf("English catalog = %+v", english)
	}
	persian := Catalog(LocalePersian)
	if persian.Locale != LocalePersian || persian.Direction != "rtl" {
		t.Fatalf("Persian catalog = %+v", persian)
	}
	for name, value := range map[string]string{
		"ready title": persian.Text.ReadyTitle, "wrong password": persian.Text.WrongPassword,
		"revealed title": persian.Text.RevealedTitle, "unavailable title": persian.Text.UnavailableTitle,
		"network title": persian.Text.NetworkTitle, "session lost": persian.Text.SessionLostTitle,
	} {
		if value == "" {
			t.Errorf("Persian %s is empty", name)
		}
	}
}
