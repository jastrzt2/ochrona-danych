import base64
import io
import qrcode


def generate_qr_code(provisioning_uri):
    qr = qrcode.QRCode(box_size=10, border=5)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    img = qr.make_image(fill='black', back_color='white')

    img_io = io.BytesIO()
    img.save(img_io, format='PNG')
    img_io.seek(0)
    qr_code_base64 = base64.b64encode(img_io.read()).decode('utf-8')
    return qr_code_base64