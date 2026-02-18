from pydantic_settings import BaseSettings

class EnvVariables(BaseSettings):
    VT_API_KEY: str
    AIPDB_API_KEY: str
    GN_API_KEY: str
    SHODAN_API_KEY: str

    class Config:
        env_file = ".env"

env_variables = EnvVariables()