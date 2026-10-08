package framework

import "testing"

func TestAgnHostImage(t *testing.T) {
	t.Run("uses full image override", func(t *testing.T) {
		options := Options{
			TestImageRegistry: "registry.example.com",
			TestAgnHostImage:  "registry.example.com/custom/agnhost:2.45",
		}

		if got, want := options.AgnHostImage(), options.TestAgnHostImage; got != want {
			t.Fatalf("AgnHostImage() = %q, want %q", got, want)
		}
	})

	t.Run("falls back to the existing repository", func(t *testing.T) {
		options := Options{TestImageRegistry: "registry.example.com"}

		if got, want := options.AgnHostImage(), "registry.example.com/e2e-test-images/agnhost:2.45"; got != want {
			t.Fatalf("AgnHostImage() = %q, want %q", got, want)
		}
	})
}
