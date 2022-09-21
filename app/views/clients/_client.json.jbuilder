json.extract! client, :id, :name, :app_id, :app_secret, :created_at, :updated_at
json.url client_url(client, format: :json)
