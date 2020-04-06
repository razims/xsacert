package main

import (
	"fmt"
	"github.com/go-acme/lego/v3/certificate"
	"github.com/go-acme/lego/v3/lego"
	"github.com/go-acme/lego/v3/registration"
	"github.com/razims/xsacert/providers/dns/namedotcom"
	"github.com/razims/xsacert/storage"
	"log"
	"os"
	"regexp"

	"github.com/urfave/cli/v2"
)

var (
	version = "1.0.0"
)

func main() {
	app := &cli.App{
		Name: "XSACert",
		Usage: "XSA Certificate manager  ",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "domain",
				Aliases:  []string{"d"},
				Usage:    "Domain or wildcard domain to obtain certificate",
				Required: true,
			},
			&cli.StringFlag{
				Name:     "email",
				Aliases:  []string{"e"},
				Usage:    "Email Address",
				Required: true,
			},
			&cli.StringFlag{
				Name:     "api-key",
				Aliases:  []string{"k"},
				Usage:    "Name.Com Api Key",
				Required: true,
			},
			&cli.StringFlag{
				Name:     "api-user",
				Aliases:  []string{"u"},
				Usage:    "Name.Com Username",
				Required: true,
			},
			&cli.StringFlag{
				Name:        "api-server",
				Aliases:     []string{"s"},
				Usage:       "Name.Com Api Server",
				Required:    false,
				Value:       "api.name.com",
			},
		},
		Action: func(c *cli.Context) error {
			domain := c.String("domain")
			email := c.String("email")
			apiHost := c.String("api-server")
			apiUser := c.String("api-user")
			apiKey := c.String("api-key")

			re := regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
			if !re.MatchString(email) {
				log.Fatal("Wrong Email address")
			}

			privateKey, err := storage.GetUserPrivateKey(email)
			if err != nil {
				log.Fatal(err)
			}

			user := CertUser{
				Email: email,
				key:   privateKey,
			}

			config := lego.NewConfig(&user)
			config.UserAgent = fmt.Sprintf("xsacert/%s", version)

			// A client facilitates communication with the CA server.
			client, err := lego.NewClient(config)
			if err != nil {
				log.Fatal(err)
			}

			// New users will need to register
			reg, err := client.Registration.Register(registration.RegisterOptions{
				TermsOfServiceAgreed: true,
			})
			if err != nil {
				log.Fatal(err)
			}
			user.Registration = reg

			provider, err := namedotcom.NewDNSProvider(apiUser, apiKey, apiHost)
			if err != nil {
				log.Fatal(err)
			}
			err = client.Challenge.SetDNS01Provider(provider)

			request := certificate.ObtainRequest{
				Domains: []string{domain},
			}
			certificates, err := client.Certificate.Obtain(request)
			if err != nil {
				log.Fatal(err)
			}

			storage.SetDomainPrivateKey(domain, certificates.PrivateKey)
			storage.SetDomainCertificate(domain, certificates.Certificate)
			storage.SetDomainIssuerCertificate(domain, certificates.IssuerCertificate)
			storage.CreateFullChainCertificate(domain)

			return nil
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
