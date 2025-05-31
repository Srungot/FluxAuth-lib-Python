from flux import Flux

flux = Flux("cmb584tgn004fp201cf055ku6", "sk-f00rmrai2u1c0hozk3tp0o2f", debug=True)

try:
    license_key = input("Enter your license key: ")
    flux.authenticate(license_key, flux.GetUserHwid())
    
    print(f"License timestamp: {flux.unix_to_datetime(flux.license_timestamp)}")
    print(f"License revoked: {flux.license_revoked}")
    print(f"License created at: {flux.unix_to_datetime(flux.license_created_at)}")
    print(f"License updated at: {flux.unix_to_datetime(flux.license_updated_at)}")
    print(f"License ID: {flux.license_id}")
    print(f"License HWID: {flux.license_hwid}")
    print(f"License expires at: {flux.license_expires_at}")
except Exception as e:
    print(f"Error: {str(e)}") 