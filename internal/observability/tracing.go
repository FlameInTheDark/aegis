package observability

import (
	"context"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	sdkresource "go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

// TracerProvider wraps the OTel provider; disabled mode uses a noop provider
// so instrumentation carries zero overhead when telemetry is off.
type TracerProvider struct {
	provider trace.TracerProvider
	enabled  bool
}

// InitTracing configures OTLP export when endpoint is non-empty.
func InitTracing(ctx context.Context, endpoint, service string, sampleRatio float64) (*TracerProvider, error) {
	if endpoint == "" {
		otel.SetTracerProvider(noop.NewTracerProvider())
		otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
			propagation.TraceContext{}, propagation.Baggage{}))
		return &TracerProvider{provider: noop.NewTracerProvider()}, nil
	}
	exporter, err := otlptracegrpc.New(ctx,
		otlptracegrpc.WithEndpoint(endpoint),
		otlptracegrpc.WithInsecure())
	if err != nil {
		return nil, err
	}
	if sampleRatio <= 0 || sampleRatio > 1 {
		sampleRatio = 0.05
	}
	res, err := sdkresource.New(ctx,
		sdkresource.WithAttributes(semconv.ServiceName(service)),
		sdkresource.WithSchemaURL(semconv.SchemaURL))
	if err != nil {
		return nil, err
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter, sdktrace.WithBatchTimeout(5*time.Second)),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.TraceIDRatioBased(sampleRatio)),
	)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{}, propagation.Baggage{}))
	return &TracerProvider{provider: tp, enabled: true}, nil
}

// Tracer returns a named tracer.
func (t *TracerProvider) Tracer(name string) trace.Tracer {
	return t.provider.Tracer(name)
}

// Shutdown flushes pending spans.
func (t *TracerProvider) Shutdown(ctx context.Context) error {
	if tp, ok := t.provider.(*sdktrace.TracerProvider); ok {
		return tp.Shutdown(ctx)
	}
	return nil
}
