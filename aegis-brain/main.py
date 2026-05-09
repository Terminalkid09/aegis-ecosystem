from fastapi import FastAPI
import os

app = FastAPI(title="Aegis-Brain Analysis Engine")

@app.get("/")
async def root():
    return {"message": "Aegis-Brain is active and analyzing"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
