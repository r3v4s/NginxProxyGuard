package repository

import (
	"context"
	"testing"
	"time"

	"nginx-proxy-guard/internal/database"
	"nginx-proxy-guard/internal/model"
)

// An update that fails half-way through its items must leave the list as it
// was. Outside a transaction it was left with the items inserted so far,
// possibly none, and a list without items writes no rules for its hosts.
func TestAccessListUpdateKeepsItemsWhenAnInsertFails(t *testing.T) {
	db, _ := openSchemaTestDB(t)
	mustExec(t, db,
		`CREATE TABLE access_lists (id uuid DEFAULT gen_random_uuid() PRIMARY KEY, name varchar(255) NOT NULL, description text,
			satisfy_any boolean DEFAULT true, pass_auth boolean DEFAULT false,
			created_at timestamptz DEFAULT now(), updated_at timestamptz DEFAULT now())`,
		`CREATE TABLE access_list_items (id uuid DEFAULT gen_random_uuid() PRIMARY KEY, access_list_id uuid NOT NULL,
			directive varchar(10) NOT NULL CHECK (directive IN ('allow', 'deny')), address varchar(255) NOT NULL,
			description text, sort_order integer DEFAULT 0, created_at timestamptz DEFAULT now(), hostname varchar(253))`,
	)
	repo := NewAccessListRepository(&database.DB{DB: db})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	list, err := repo.Create(ctx, &model.CreateAccessListRequest{Name: "partners", Items: []model.CreateAccessListItemRequest{
		{Directive: "allow", Address: "192.0.2.0/24", SortOrder: 1},
		{Directive: "deny", Address: "all", SortOrder: 2},
	}})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	newName := "partners-renamed"
	_, err = repo.Update(ctx, list.ID, &model.UpdateAccessListRequest{Name: &newName, Items: []model.CreateAccessListItemRequest{
		{Directive: "allow", Address: "198.51.100.0/24", SortOrder: 1},
		{Directive: "nope", Address: "all", SortOrder: 2}, // fails the CHECK after the first insert
	}})
	if err == nil {
		t.Fatal("the update was expected to fail on its second item")
	}

	got, err := repo.GetByID(ctx, list.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "partners" {
		t.Errorf("name = %q, the failed update's rename was kept", got.Name)
	}
	if len(got.Items) != 2 || got.Items[0].Address != "192.0.2.0/24" || got.Items[1].Address != "all" {
		t.Errorf("items = %+v, want the two items from before the failed update", got.Items)
	}
}

func TestAccessListCreateWritesNothingWhenAnItemFails(t *testing.T) {
	db, _ := openSchemaTestDB(t)
	mustExec(t, db,
		`CREATE TABLE access_lists (id uuid DEFAULT gen_random_uuid() PRIMARY KEY, name varchar(255) NOT NULL, description text,
			satisfy_any boolean DEFAULT true, pass_auth boolean DEFAULT false,
			created_at timestamptz DEFAULT now(), updated_at timestamptz DEFAULT now())`,
		`CREATE TABLE access_list_items (id uuid DEFAULT gen_random_uuid() PRIMARY KEY, access_list_id uuid NOT NULL,
			directive varchar(10) NOT NULL CHECK (directive IN ('allow', 'deny')), address varchar(255) NOT NULL,
			description text, sort_order integer DEFAULT 0, created_at timestamptz DEFAULT now(), hostname varchar(253))`,
	)
	repo := NewAccessListRepository(&database.DB{DB: db})
	_, err := repo.Create(context.Background(), &model.CreateAccessListRequest{Name: "half", Items: []model.CreateAccessListItemRequest{
		{Directive: "allow", Address: "192.0.2.0/24"},
		{Directive: "nope", Address: "all"},
	}})
	if err == nil {
		t.Fatal("the create was expected to fail on its second item")
	}
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM access_lists`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("%d access list(s) left behind by a failed create", n)
	}
}
