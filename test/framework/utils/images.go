package utils

// Container images the integration suites run. Kept here rather than in the
// specs, so one image bump is one edit, and so the two groups below stay
// visibly separate.

// Images under the test image registry, which callers prefix with
// Options.TestImageRegistry (the --test-image-registry flag). That registry is
// replicated to regions without internet access, which cannot pull from
// public.ecr.aws at all, so a spec that needs to run there has to use one of
// these.
const (
	NginxImage = "networking-e2e-test-images/nginx:1.31.6"
)

// Images pulled straight from public.ecr.aws, because no copy of them is
// replicated to the test image registry today. A spec that uses one of these
// cannot run in a region without internet access, so prefer an image from the
// group above when the spec has a choice.
const (
	PythonImage             = "public.ecr.aws/docker/library/python:3.11-slim"
	AmazonLinuxMinimalImage = "public.ecr.aws/amazonlinux/amazonlinux:2023-minimal"
)
