import spacy
nlp = spacy.load("en_core_web_sm")

def extract_location(query):
    doc = nlp(query)
    for ent in doc.ents:
        if ent.label_ == "GPE":  # Geo-Political Entity (city, country)
            return ent.text
    # Fallback: keyword matching for common locations
    query_lower = query.lower()
    locations = ["nairobi", "eldoret", "mombasa", "kisumu", "nakuru", "thika", "kitale", "garissa", "nyeri", "meru", "machakos", "kericho", "malindi", "kilifi", "embu", "isiolo", "lamu", "busia", "bungoma", "homa bay", "migori", "narok", "nyahururu", "vihiga", "wajir", "marsabit", "turkana"]
    for loc in locations:
        if loc in query_lower:
            return loc.title()
    return None
