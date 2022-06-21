package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/jetstack/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/acme/webhook/cmd"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
)

const DnsRecordTtl = 300

var GroupName = os.Getenv("GROUP_NAME")

func main() {
	if GroupName == "" {
		panic("You must specify the webhook group name in (Cluster)Issuer resource's .spec.acme.solvers[dns01].webhook.groupName setting.")
	}

	// This will register our Yandex.Connect DNS provider with the webhook serving
	// library, making it available as an API under the provided GroupName.
	// You can register multiple DNS provider implementations with a single
	// webhook, where the Name() method will be used to disambiguate between
	// the different implementations.
	cmd.RunWebhookServer(GroupName, &yandexConnectDNSProviderSolver{})
}

// yandexConnectDNSProviderSolver implements the provider-specific logic needed to
// 'present' an ACME challenge TXT record for your own DNS provider.
// To do so, it must implement the `github.com/jetstack/cert-manager/pkg/acme/webhook.Solver`
// interface.
type yandexConnectDNSProviderSolver struct {
	client *kubernetes.Clientset
}

// yandexConnectDNSProviderConfig is a structure that is used to decode into when
// solving a DNS01 challenge.
// This information is provided by cert-manager, and may be a reference to
// additional configuration that's needed to solve the challenge for this
// particular certificate or issuer.
// This typically includes references to Secret resources containing DNS
// provider credentials, in cases where a 'multi-tenant' DNS solver is being
// created.
// If you do *not* require per-issuer or per-certificate configuration to be
// provided to your webhook, you can skip decoding altogether in favour of
// using CLI flags or similar to provide configuration.
// You should not include sensitive information here. If credentials need to
// be used by your provider here, you should reference a Kubernetes Secret
// resource and fetch these credentials using a Kubernetes clientset.
type yandexConnectDNSProviderConfig struct {
	// These fields will be set by users in the
	// `issuer.spec.acme.dns01.providers.webhook.config` field.
	PddTokenSecretRef cmmeta.SecretKeySelector `json:"pddTokenSecretRef"`
}

// Name is used as the name for this DNS solver when referencing it on the ACME
// Issuer resource.
// This should be unique **within the group name**, i.e. you can have two
// solvers configured with the same Name() **so long as they do not co-exist
// within a single webhook deployment**.
// For example, `cloudflare` may be used as the name of a solver.
func (solver *yandexConnectDNSProviderSolver) Name() string {
	return "yandexConnect"
}

// Present is responsible for actually presenting the DNS record with the
// DNS provider.
// This method should tolerate being called multiple times with the same value.
// cert-manager itself will later perform a self check to ensure that the
// solver has correctly configured the DNS provider.
func (solver *yandexConnectDNSProviderSolver) Present(challengeRequest *v1alpha1.ChallengeRequest) error {
	klog.V(6).Infof("call function Present: namespace=%s, zone=%s, fqdn=%s",
		challengeRequest.ResourceNamespace, challengeRequest.ResolvedZone, challengeRequest.ResolvedFQDN)

	configuration, error := loadConfig(challengeRequest.Config)
	if error != nil {
		return fmt.Errorf("unable to load config: %v", error)
	}

	klog.V(6).Infof("decoded configuration %v", configuration)

	pddToken, error := solver.getPddToken(&configuration, challengeRequest.ResourceNamespace)
	if error != nil {
		return fmt.Errorf("unable to get PDD Token: %v", error)
	}

	yandexConnectClient := NewYandexConnectClient(*pddToken)

	entry, domain := solver.getDomainAndEntry(challengeRequest)
	klog.V(6).Infof("present for entry=%s, domain=%s", entry, domain)

	isRecordPresent, error := yandexConnectClient.HasTxtRecord(&domain, &entry)
	if error != nil {
		return fmt.Errorf("unable to check TXT record: %v", error)
	}

	if isRecordPresent {
		error := yandexConnectClient.UpdateTxtRecord(&domain, &entry, &challengeRequest.Key, DnsRecordTtl)
		if error != nil {
			return fmt.Errorf("unable to change TXT record: %v", error)
		}
	} else {
		error := yandexConnectClient.CreateTxtRecord(&domain, &entry, &challengeRequest.Key, DnsRecordTtl)
		if error != nil {
			return fmt.Errorf("unable to create TXT record: %v", error)
		}
	}

	return nil
}

// CleanUp should delete the relevant TXT record from the DNS provider console.
// If multiple TXT records exist with the same record name (e.g.
// _acme-challenge.example.com) then **only** the record with the same `key`
// value provided on the ChallengeRequest should be cleaned up.
// This is in order to facilitate multiple DNS validations for the same domain
// concurrently.
func (solver *yandexConnectDNSProviderSolver) CleanUp(challengeRequest *v1alpha1.ChallengeRequest) error {
	klog.V(6).Infof("call function CleanUp: namespace=%s, zone=%s, fqdn=%s",
		challengeRequest.ResourceNamespace, challengeRequest.ResolvedZone, challengeRequest.ResolvedFQDN)

	configuration, error := loadConfig(challengeRequest.Config)
	if error != nil {
		return error
	}

	pddToken, error := solver.getPddToken(&configuration, challengeRequest.ResourceNamespace)
	if error != nil {
		return fmt.Errorf("unable to get API key: %v", error)
	}

	yandexConnectClient := NewYandexConnectClient(*pddToken)

	entry, domain := solver.getDomainAndEntry(challengeRequest)

	isRecordPresent, error := yandexConnectClient.HasTxtRecord(&domain, &entry)
	if error != nil {
		return fmt.Errorf("unable to check TXT record: %v", error)
	}

	if isRecordPresent {
		klog.V(6).Infof("deleting entry=%s, domain=%s", entry, domain)
		error := yandexConnectClient.DeleteTxtRecord(&domain, &entry)
		if error != nil {
			return fmt.Errorf("unable to remove TXT record: %v", error)
		}
	}

	return nil
}

// Initialize will be called when the webhook first starts.
// This method can be used to instantiate the webhook, i.e. initializing
// connections or warming up caches.
// Typically, the kubeClientConfig parameter is used to build a Kubernetes
// client that can be used to fetch resources from the Kubernetes API, e.g.
// Secret resources containing credentials used to authenticate with DNS
// provider accounts.
// The stopCh can be used to handle early termination of the webhook, in cases
// where a SIGTERM or similar signal is sent to the webhook process.
func (solver *yandexConnectDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, _ <-chan struct{}) error {
	klog.V(6).Infof("call function Initialize")
	clientset, error := kubernetes.NewForConfig(kubeClientConfig)
	if error != nil {
		return fmt.Errorf("unable to get k8s client: %v", error)
	}

	solver.client = clientset
	return nil
}

// Decodes JSON configuration into the typed config struct.
func loadConfig(configurationJSON *extapi.JSON) (yandexConnectDNSProviderConfig, error) {
	configuration := yandexConnectDNSProviderConfig{}
	// Handle the 'base case' where no configuration has been provided.
	if configurationJSON == nil {
		return configuration, nil
	}
	if error := json.Unmarshal(configurationJSON.Raw, &configuration); error != nil {
		return configuration, fmt.Errorf("error decoding solver config: %v", error)
	}

	return configuration, nil
}

// Gets domain and entry from cert-manager's challenge request.
func (solver *yandexConnectDNSProviderSolver) getDomainAndEntry(challengeRequest *v1alpha1.ChallengeRequest) (string, string) {
	// Both challengeRequest.ResolvedZone and challengeRequest.ResolvedFQDN end with a dot: '.'
	entry := strings.TrimSuffix(challengeRequest.ResolvedFQDN, challengeRequest.ResolvedZone)
	entry = strings.TrimSuffix(entry, ".")
	domain := strings.TrimSuffix(challengeRequest.ResolvedZone, ".")
	return entry, domain
}

// Gets Yandex.Connect PDD token from Kubernetes secret.
func (solver *yandexConnectDNSProviderSolver) getPddToken(config *yandexConnectDNSProviderConfig, namespace string) (*string, error) {
	secretName := config.PddTokenSecretRef.LocalObjectReference.Name

	klog.V(6).Infof("try to load secret `%s` with key `%s`", secretName, config.PddTokenSecretRef.Key)

	secret, error := solver.client.CoreV1().Secrets(namespace).Get(context.Background(), secretName, metav1.GetOptions{})
	if error != nil {
		return nil, fmt.Errorf("unable to get secret `%s`; %v", secretName, error)
	}

	secretContent, isFound := secret.Data[config.PddTokenSecretRef.Key]
	if !isFound {
		return nil, fmt.Errorf("key %q not found in secret \"%s/%s\"", config.PddTokenSecretRef.Key,
			config.PddTokenSecretRef.LocalObjectReference.Name, namespace)
	}

	pddToken := string(secretContent)
	return &pddToken, nil
}
