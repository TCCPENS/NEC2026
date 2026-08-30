CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, role TEXT);
INSERT OR IGNORE INTO users VALUES (1, 'catalogue_guest', 'pond-notebook-2026', 'user');
CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY, name TEXT, price TEXT, description TEXT, stock TEXT, accent TEXT);
INSERT OR IGNORE INTO products VALUES
(1,'Scarlet Skimmer','$84.00','A vivid marsh companion for collectors and field photographers.','In stock','scarlet'),
(2,'Blue Dasher','$72.00','Quiet, quick, and suited to observation setups.','In stock','blue'),
(3,'Golden-Wing Dragonfly','$119.00','Warm amber wings with a distinctive late-summer profile.','Low stock','gold'),
(4,'Emerald Hunter','$96.00','A forest-edge species with deep green thorax markings.','In stock','emerald'),
(5,'Crimson Marsh Dragonfly','$138.00','A rare wetland specimen documented by our field team.','Pre-order','crimson');
