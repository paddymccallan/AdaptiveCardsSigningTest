using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace AdaptiveCardSigningTest
{
    class Program
    {
        static void Main(string[] args)
        {
            byte[] certBytes = Convert.FromBase64String("YOUR PRIVATE KEY HERE");
            X509Certificate2 cert = new X509Certificate2(certBytes, (string)null, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.DefaultKeySet | X509KeyStorageFlags.Exportable);

            //Changing this line to var privateKey = new RsaSecurityKey(cert.GetRSAPublicKey()); has the same result!
            var privateKey = new RsaSecurityKey(cert.GetRSAPrivateKey());
            
            //Create the token and sign it
            SigningCredentials signingCredentials = new SigningCredentials(privateKey, SecurityAlgorithms.RsaSha256Signature);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(
                new Claim[]
                {
                                new Claim("sender", "your_email@something.com"),
                                new Claim("originator", "8Ocbd2a9-3f42-43b5-87bd-8574ff48cd3e"),
                                new Claim("recipientsSerialized", "...list of recipients..."),
                                new Claim("adaptiveCardSerialized", "...adaptive card serialized..."),
                }),
                IssuedAt = DateTime.UtcNow,
                Expires = DateTime.UtcNow.AddDays(7),
                SigningCredentials = signingCredentials
            };

            //Create the JWT token
            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
            handler.SetDefaultTimesOnTokenCreation = false;
            var token = handler.CreateJwtSecurityToken(tokenDescriptor);

            //Validate it now with the public key
            {
                var rsa = new RSACryptoServiceProvider();
                rsa.FromXmlString("<RSAKeyValue><Modulus>[YOUR, PUBLIC KEY IN HERE]</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>");
                SecurityKey publicKey = new RsaSecurityKey(rsa);
                var tokenValidationParameters = new TokenValidationParameters()
                {
                    ValidateActor = false,
                    ValidateAudience = false,
                    ValidateIssuer = false,
                    ValidateIssuerSigningKey = true,
                    ValidateLifetime = false,
                    IssuerSigningKey = publicKey,
                };

                var validatedClaimsPrincipal = handler.ValidateToken(token.RawData, tokenValidationParameters, out SecurityToken validatedToken);
                System.Console.WriteLine("Validated principal: " + validatedClaimsPrincipal.ToString());
            }
        }
    }
}
