const express = require('express')
const bodyParser = require('body-parser')
const crypto = require('crypto')
const pki = require('node-forge').pki
const fs = require('fs')

const app = express()
const port = 4444

app.use(express.static('public'))
app.use(bodyParser.urlencoded())

// get the SAP CA cert from https://support.sap.com/en/offerings-programs/support-services/trust-center-services.html
const DO_VERIFY_CA = true
const CA_CERT_G2 = fs.readFileSync('SAPPassportCA.pem', 'utf8')

function isCertIssuedByCa(certPem) {

  const ca = pki.certificateFromPem(CA_CERT_G2)
  const cert = pki.certificateFromPem(certPem)

  try {
    console.log('Verified public key with CA', ca.issuer.getField('CN'))
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