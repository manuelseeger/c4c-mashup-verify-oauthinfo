const express = require('express')
const bodyParser = require('body-parser')
const crypto = require('crypto')
const pki = require('node-forge').pki

const app = express()
const port = 4444

app.use(express.static('public'))
app.use(bodyParser.urlencoded())

// This CA cert is hardcoded in the example repo code, but it does not verify with the public key we receive from C4C
// TODO: Request the proper CA from SAP
const DO_VERIFY_CA = false
const CA_CERT = "-----BEGIN CERTIFICATE-----\n" + "MIICZjCCAc+gAwIBAgIECAAAATANBgkqhkiG9w0BAQUFADBFMQswCQYDVQQGEwJE\n"
  + "RTEcMBoGA1UEChMTU0FQIFRydXN0IENvbW11bml0eTEYMBYGA1UEAxMPU0FQIFBh\n"
  + "c3Nwb3J0IENBMB4XDTAwMDcxODEwMDAwMFoXDTIxMDQwMTEwMDAwMFowRTELMAkG\n"
  + "A1UEBhMCREUxHDAaBgNVBAoTE1NBUCBUcnVzdCBDb21tdW5pdHkxGDAWBgNVBAMT\n"
  + "D1NBUCBQYXNzcG9ydCBDQTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA/2rT\n"
  + "TxBHa450XQCJ/ENotmAwKpFdyKWdU7KC4p8X0VEz/DB4Zu5Digq91f9wxsAYyvbh\n"
  + "hvoZ5nZimr1sFiWw60gCryDI2qINowZX/sWmYGqguVyBrTxjjEwnAYQXno53RFR5\n"
  + "p0Aa9RLfLNSITWeHeELKT5ahpGckGdrh4R6+vSMCAwEAAaNjMGEwDwYDVR0TAQH/\n"
  + "BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAfYwHQYDVR0OBBYEFBpERaZXcXBWARx4JHpR\n"
  + "NkzANdBeMB8GA1UdIwQYMBaAFBpERaZXcXBWARx4JHpRNkzANdBeMA0GCSqGSIb3\n"
  + "DQEBBQUAA4GBACwoEOHrYBA0pt7ClKyLfO2o2aJ1DyGCkzrM7RhStTE1yfCpiagc\n"
  + "XUYu4yCM1i7jPnAWkpMe1NhpwEEbiKPAa3jLJ7iIXN3e/qZG0HAyPOQS3KdAQsiC\n"
  + "bL9ysfX0LqKir68z0Tv0SYtJTMnPfkCtGXt+D75wWSY7dyI0Xu7Yl9kH\n" + "-----END CERTIFICATE-----"

function isCertIssuedByCa(certPem) {

  const ca = pki.certificateFromPem(CA_CERT)
  const cert = pki.certificateFromPem(certPem)

  try {
    return ca.verify(cert)
  } catch (e) {
    console.log(e)
    return false;
  }
}

app.post('/verify', function (req, res) {
  res.setHeader('Content-Type', 'application/json')
  let result;

  const verifier = crypto.createVerify('sha1WithRSAEncryption')
  const oAuthInfo = JSON.parse(req.body.payload)
  const signature = oAuthInfo.signature
  
  const buff = Buffer.from(oAuthInfo.OAuthInfo, 'base64')
  const payloadStr = buff.toString('utf-8')
  const payloadJSON = JSON.parse(payloadStr)
  console.log(payloadJSON)

  const publicKey = convertCertificate(payloadJSON.base64_cert)

  if (!DO_VERIFY_CA || isCertIssuedByCa(publicKey)) {

    verifier.update(oAuthInfo.OAuthInfo)

    verifiedSignature = verifier.verify(publicKey, signature, signatureEncoding='base64')

    console.log(verifiedSignature)

    result = {
      UserID: payloadJSON.user, 
      Verified: verifiedSignature
    }
  } else {
    result = {
      UserID: payloadJSON.user, 
      Verified: false
    }
  }
  res.end(JSON.stringify(result))
})

app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`)
})

// crypto verifier expects the public key in strict PEM with 
// 64 char line breaks
function convertCertificate (cert) {
  var beginCert = "-----BEGIN CERTIFICATE-----"
  var endCert = "-----END CERTIFICATE-----"

  cert = cert.replace("\n", "")
  cert = cert.replace(beginCert, "")
  cert = cert.replace(endCert, "")

  var result = beginCert
  while (cert.length > 0) {

      if (cert.length > 64) {
          result += "\n" + cert.substring(0, 64)
          cert = cert.substring(64, cert.length)
      }
      else {
          result += "\n" + cert
          cert = ""
      }
  }

  if (result[result.length ] != "\n")
      result += "\n"
  result += endCert + "\n"
  return result
}