package idp

import (
	"fmt"

	"github.com/crewjam/saml"
)

type OpenIdConnectAssertionMaker struct{}

func (OpenIdConnectAssertionMaker) MakeAssertion(req *saml.IdpAuthnRequest, session *saml.Session) error {
	attributes := []saml.Attribute{}

	var attributeConsumingService *saml.AttributeConsumingService
	for _, acs := range req.SPSSODescriptor.AttributeConsumingServices {
		if acs.IsDefault != nil && *acs.IsDefault {
			// explicitly copy loop iterator variables
			//
			// c.f. https://github.com/golang/go/wiki/CommonMistakes#using-reference-to-loop-iterator-variable
			//
			// (note that I'm pretty sure this isn't strictly necessary because we break out of the loop immediately,
			// but it certainly doesn't hurt anything and may prevent bugs in the future.)
			acs := acs

			attributeConsumingService = &acs
			break
		}
	}
	if attributeConsumingService == nil {
		for _, acs := range req.SPSSODescriptor.AttributeConsumingServices {
			// explicitly copy loop iterator variables
			//
			// c.f. https://github.com/golang/go/wiki/CommonMistakes#using-reference-to-loop-iterator-variable
			//
			// (note that I'm pretty sure this isn't strictly necessary because we break out of the loop immediately,
			// but it certainly doesn't hurt anything and may prevent bugs in the future.)
			acs := acs

			attributeConsumingService = &acs
			break
		}
	}
	if attributeConsumingService == nil {
		attributeConsumingService = &saml.AttributeConsumingService{}
	}

	if session.UserName != "" {
		attributes = append(attributes, saml.Attribute{
			FriendlyName: "uid",
			Name:         "urn:oid:0.9.2342.19200300.100.1.1",
			NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			Values: []saml.AttributeValue{{
				Type:  "xs:string",
				Value: session.UserName,
			}},
		})
	}

	if session.UserEmail != "" {
		attributes = append(attributes, saml.Attribute{
			FriendlyName: "eduPersonPrincipalName",
			Name:         "urn:oid:1.3.6.1.4.1.5923.1.1.1.6",
			NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			Values: []saml.AttributeValue{{
				Type:  "xs:string",
				Value: session.UserEmail,
			}},
		})
	}
	if session.UserSurname != "" {
		attributes = append(attributes, saml.Attribute{
			FriendlyName: "sn",
			Name:         "urn:oid:2.5.4.4",
			NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			Values: []saml.AttributeValue{{
				Type:  "xs:string",
				Value: session.UserSurname,
			}},
		})
	}
	if session.UserGivenName != "" {
		attributes = append(attributes, saml.Attribute{
			FriendlyName: "givenName",
			Name:         "urn:oid:2.5.4.42",
			NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			Values: []saml.AttributeValue{{
				Type:  "xs:string",
				Value: session.UserGivenName,
			}},
		})
	}

	attributes = append(attributes, session.CustomAttributes...)

	// allow for some clock skew in the validity period using the
	// issuer's apparent clock.
	notBefore := req.Now.Add(-1 * saml.MaxClockSkew)
	notOnOrAfterAfter := req.Now.Add(saml.MaxIssueDelay)
	if notBefore.Before(req.Request.IssueInstant) {
		notBefore = req.Request.IssueInstant
		notOnOrAfterAfter = notBefore.Add(saml.MaxIssueDelay)
	}

	req.Assertion = &saml.Assertion{
		ID:           fmt.Sprintf("id-%x", randomBytes(20)),
		IssueInstant: saml.TimeNow(),
		Version:      "2.0",
		Issuer: saml.Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  req.IDP.Metadata().EntityID,
		},
		Subject: &saml.Subject{
			NameID: &saml.NameID{
				Format:          "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
				NameQualifier:   req.IDP.Metadata().EntityID,
				SPNameQualifier: req.ServiceProviderMetadata.EntityID,
				Value:           session.NameID,
			},
			SubjectConfirmations: []saml.SubjectConfirmation{
				{
					Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
					SubjectConfirmationData: &saml.SubjectConfirmationData{
						Address:      req.HTTPRequest.RemoteAddr,
						InResponseTo: req.Request.ID,
						NotOnOrAfter: req.Now.Add(saml.MaxIssueDelay),
						Recipient:    req.ACSEndpoint.Location,
					},
				},
			},
		},
		Conditions: &saml.Conditions{
			NotBefore:    notBefore,
			NotOnOrAfter: notOnOrAfterAfter,
			AudienceRestrictions: []saml.AudienceRestriction{
				{
					Audience: saml.Audience{Value: req.ServiceProviderMetadata.EntityID},
				},
			},
		},
		AuthnStatements: []saml.AuthnStatement{
			{
				AuthnInstant: session.CreateTime,
				SessionIndex: session.Index,
				SubjectLocality: &saml.SubjectLocality{
					Address: req.HTTPRequest.RemoteAddr,
				},
				AuthnContext: saml.AuthnContext{
					AuthnContextClassRef: &saml.AuthnContextClassRef{
						Value: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
					},
				},
			},
		},
		AttributeStatements: []saml.AttributeStatement{
			{
				Attributes: attributes,
			},
		},
	}

	return nil
}
