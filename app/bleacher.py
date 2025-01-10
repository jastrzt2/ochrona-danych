from bleach import clean

allowed_tags = [
    'p', 'ul', 'img', 'li', 'ol', 'strong', 'em', 'a', 'blockquote', 'code', 'pre',
    'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'hr', 'br'
]
allowed_attributes = {
    'a': ['href', 'title'],
    'img': ['src', 'alt']
}

def bleach_html(html_content):
    bleached_html = clean(html_content, tags=allowed_tags, attributes=allowed_attributes)
    
    return bleached_html