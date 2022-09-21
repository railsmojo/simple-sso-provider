class CreateAccessGrants < ActiveRecord::Migration[7.0]
  def change
    create_table :access_grants do |t|
      t.belongs_to :user, null: false, foreign_key: true
      t.belongs_to :client, null: false, foreign_key: true
      t.string :code
      t.string :access_token
      t.string :refresh_token
      t.datetime :access_token_expires_at
      t.string :state

      t.timestamps
    end
  end
end
