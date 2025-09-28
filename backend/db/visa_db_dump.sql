--
-- PostgreSQL database dump
--

\restrict CHJ7LsaNFcDNNvUycG5v4FJFCShbAh9RGlgQ9u7gOGn2emrB2kJHRRqVAtWoTaa

-- Dumped from database version 14.19 (Homebrew)
-- Dumped by pg_dump version 14.19 (Homebrew)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: address; Type: TABLE; Schema: public; Owner: armaanbudhiraja
--

CREATE TABLE public.address (
    id integer NOT NULL,
    user_id integer NOT NULL,
    full_name character varying(100) NOT NULL,
    phone character varying(15),
    line1 character varying(255) NOT NULL,
    line2 character varying(255),
    city character varying(100) NOT NULL,
    state character varying(100) NOT NULL,
    pincode character varying(20) NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);


ALTER TABLE public.address OWNER TO armaanbudhiraja;

--
-- Name: addresses_id_seq; Type: SEQUENCE; Schema: public; Owner: armaanbudhiraja
--

CREATE SEQUENCE public.addresses_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.addresses_id_seq OWNER TO armaanbudhiraja;

--
-- Name: addresses_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: armaanbudhiraja
--

ALTER SEQUENCE public.addresses_id_seq OWNED BY public.address.id;


--
-- Name: cart_items; Type: TABLE; Schema: public; Owner: armaanbudhiraja
--

CREATE TABLE public.cart_items (
    id integer NOT NULL,
    user_id integer,
    product_id integer,
    quantity integer DEFAULT 1,
    size character varying(10),
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);


ALTER TABLE public.cart_items OWNER TO armaanbudhiraja;

--
-- Name: cart_items_id_seq; Type: SEQUENCE; Schema: public; Owner: armaanbudhiraja
--

CREATE SEQUENCE public.cart_items_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.cart_items_id_seq OWNER TO armaanbudhiraja;

--
-- Name: cart_items_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: armaanbudhiraja
--

ALTER SEQUENCE public.cart_items_id_seq OWNED BY public.cart_items.id;


--
-- Name: order_items; Type: TABLE; Schema: public; Owner: armaanbudhiraja
--

CREATE TABLE public.order_items (
    id integer NOT NULL,
    order_id integer,
    product_id integer,
    quantity integer NOT NULL,
    size character varying(10)
);


ALTER TABLE public.order_items OWNER TO armaanbudhiraja;

--
-- Name: order_items_id_seq; Type: SEQUENCE; Schema: public; Owner: armaanbudhiraja
--

CREATE SEQUENCE public.order_items_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.order_items_id_seq OWNER TO armaanbudhiraja;

--
-- Name: order_items_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: armaanbudhiraja
--

ALTER SEQUENCE public.order_items_id_seq OWNED BY public.order_items.id;


--
-- Name: orders; Type: TABLE; Schema: public; Owner: armaanbudhiraja
--

CREATE TABLE public.orders (
    id integer NOT NULL,
    user_id integer,
    address_id integer,
    total numeric(10,2) NOT NULL,
    payment_method character varying(50),
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);


ALTER TABLE public.orders OWNER TO armaanbudhiraja;

--
-- Name: orders_id_seq; Type: SEQUENCE; Schema: public; Owner: armaanbudhiraja
--

CREATE SEQUENCE public.orders_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.orders_id_seq OWNER TO armaanbudhiraja;

--
-- Name: orders_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: armaanbudhiraja
--

ALTER SEQUENCE public.orders_id_seq OWNED BY public.orders.id;


--
-- Name: products; Type: TABLE; Schema: public; Owner: armaanbudhiraja
--

CREATE TABLE public.products (
    id integer NOT NULL,
    name character varying(100) NOT NULL,
    description text,
    price numeric(10,2) NOT NULL,
    image character varying(255),
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    image2 character varying(255)
);


ALTER TABLE public.products OWNER TO armaanbudhiraja;

--
-- Name: products_id_seq; Type: SEQUENCE; Schema: public; Owner: armaanbudhiraja
--

CREATE SEQUENCE public.products_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.products_id_seq OWNER TO armaanbudhiraja;

--
-- Name: products_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: armaanbudhiraja
--

ALTER SEQUENCE public.products_id_seq OWNED BY public.products.id;


--
-- Name: users; Type: TABLE; Schema: public; Owner: armaanbudhiraja
--

CREATE TABLE public.users (
    id integer NOT NULL,
    name character varying(100) NOT NULL,
    email character varying(100) NOT NULL,
    password character varying(100) NOT NULL,
    phone character varying(15),
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);


ALTER TABLE public.users OWNER TO armaanbudhiraja;

--
-- Name: users_id_seq; Type: SEQUENCE; Schema: public; Owner: armaanbudhiraja
--

CREATE SEQUENCE public.users_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.users_id_seq OWNER TO armaanbudhiraja;

--
-- Name: users_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: armaanbudhiraja
--

ALTER SEQUENCE public.users_id_seq OWNED BY public.users.id;


--
-- Name: address id; Type: DEFAULT; Schema: public; Owner: armaanbudhiraja
--

ALTER TABLE ONLY public.address ALTER COLUMN id SET DEFAULT nextval('public.addresses_id_seq'::regclass);


--
-- Name: cart_items id; Type: DEFAULT; Schema: public; Owner: armaanbudhiraja
--

ALTER TABLE ONLY public.cart_items ALTER COLUMN id SET DEFAULT nextval('public.cart_items_id_seq'::regclass);


--
-- Name: order_items id; Type: DEFAULT; Schema: public; Owner: armaanbudhiraja
--

ALTER TABLE ONLY public.order_items ALTER COLUMN id SET DEFAULT nextval('public.order_items_id_seq'::regclass);


--
-- Name: orders id; Type: DEFAULT; Schema: public; Owner: armaanbudhiraja
--

ALTER TABLE ONLY public.orders ALTER COLUMN id SET DEFAULT nextval('public.orders_id_seq'::regclass);


--
-- Name: products id; Type: DEFAULT; Schema: public; Owner: armaanbudhiraja
--

ALTER TABLE ONLY public.products ALTER COLUMN id SET DEFAULT nextval('public.products_id_seq'::regclass);


--
-- Name: users id; Type: DEFAULT; Schema: public; Owner: armaanbudhiraja
--

ALTER TABLE ONLY public.users ALTER COLUMN id SET DEFAULT nextval('public.users_id_seq'::regclass);


--
-- Data for Name: address; Type: TABLE DATA; Schema: public; Owner: armaanbudhiraja
--

COPY public.address (id, user_id, full_name, phone, line1, line2, city, state, pincode, created_at) FROM stdin;
1	2	Armaan Budhiraja	9518449833	#1292, Sector 9	Ambala City	Ambala	Haryana	134003	2025-09-16 17:18:22.039771
2	1	Armaan Budhiraja	9518449833	#1294, sector 10	Ambala City	Ambala	Haryana	134003	2025-09-16 19:34:02.327002
3	3	Armaan Budhiraja	9518449833	#1292 sector 9	Ambala City	Ambala	Haryana	134003	2025-09-17 12:36:22.614822
4	4	cvbn	dfghjk	dfghjk	dfghjk	dfghjk	dfghjk	dfghjk	2025-09-17 18:54:43.78906
5	5	nirmit	7569462818	ihujnkpougv		jhughjvj	lhugyi	343433	2025-09-22 23:56:10.795996
\.


--
-- Data for Name: cart_items; Type: TABLE DATA; Schema: public; Owner: armaanbudhiraja
--

COPY public.cart_items (id, user_id, product_id, quantity, size, created_at) FROM stdin;
\.


--
-- Data for Name: order_items; Type: TABLE DATA; Schema: public; Owner: armaanbudhiraja
--

COPY public.order_items (id, order_id, product_id, quantity, size) FROM stdin;
1	1	4	2	8
2	2	2	2	8
3	3	2	1	7
4	3	6	1	9
5	4	4	1	7
6	4	8	1	9
7	5	7	1	8
8	6	4	1	8
9	7	2	1	9
10	7	8	2	7
11	8	2	1	8
12	9	3	3	7
13	10	5	1	10
\.


--
-- Data for Name: orders; Type: TABLE DATA; Schema: public; Owner: armaanbudhiraja
--

COPY public.orders (id, user_id, address_id, total, payment_method, created_at) FROM stdin;
1	2	1	2800.00	cod	2025-09-16 17:18:28.682753
2	2	1	2800.00	cod	2025-09-16 17:37:35.808675
3	2	1	2700.00	cod	2025-09-16 18:40:17.752528
4	1	2	3200.00	cod	2025-09-16 19:34:03.23443
5	3	3	1800.00	cod	2025-09-17 12:36:50.015443
6	3	3	1400.00	cod	2025-09-17 14:18:52.598168
7	3	3	5000.00	cod	2025-09-17 14:32:09.495614
8	1	2	1400.00	cod	2025-09-17 16:25:52.494094
9	4	4	3300.00	card	2025-09-17 18:54:47.451907
10	5	5	1200.00	cod	2025-09-22 23:56:12.622058
\.


--
-- Data for Name: products; Type: TABLE DATA; Schema: public; Owner: armaanbudhiraja
--

COPY public.products (id, name, description, price, image, created_at, image2) FROM stdin;
1	Blue Canvas Shoes	Comfortable and stylish blue canvas sneakers.	1200.00	/images/shoe1.jpg	2025-09-16 16:24:06.578957	/images/shoe1_2.avif
2	Black High Tops	Classic black high-top sneakers for all occasions.	1400.00	/images/shoe2.avif	2025-09-16 16:24:06.578957	/images/shoe2_2.avif
3	Yellow Sports Shoes	Lightweight yellow sports shoes for running and training.	1100.00	/images/shoe3.avif	2025-09-16 16:24:06.578957	/images/shoe3_3.avif
4	Black High Tops	Classic black high-top sneakers for all occasions.	1400.00	/images/shoe4.avif	2025-09-16 16:24:06.578957	/images/shoe4_2.avif
5	Multicolor canvas	A pair of colorful sneakers to express your unique style.	1200.00	/images/shoe5.avif	2025-09-16 16:24:06.578957	/images/shoe5_2.avif
6	Red Sports Shoes	A pair of stylish red shoes to help you stand out.	1300.00	/images/shoe6.avif	2025-09-16 16:24:06.578957	/images/shoe6_2.avif
7	Yellow Air Jordan	A classic Nike Air Jordan design in a striking yellow.	1800.00	/images/shoe7.avif	2025-09-16 16:24:06.578957	/images/shoe7_2.avif
8	Blue Air Jordan	The classic Air Jordan in a sleek blue.	1800.00	/images/shoe8.avif	2025-09-16 16:24:06.578957	/images/shoe8_2.avif
9	Green Air Jordan	A vibrant green Air Jordan for a fresh look.	1700.00	/images/shoe9.avif	2025-09-16 16:24:06.578957	/images/shoe9_2.avif
\.


--
-- Data for Name: users; Type: TABLE DATA; Schema: public; Owner: armaanbudhiraja
--

COPY public.users (id, name, email, password, phone, created_at) FROM stdin;
1	Armaan Budhiraja	arm@gmail.com	$2b$10$JCHo3TOGTDAY6kbvQFSFou75fQyxWTC8QW2uZN0JC/jB0H9luiHRi	9518449833	2025-09-16 16:06:07.453069
2	Armaan	armaan@gmail.com	$2b$10$2bNI9SpTwZTiDX1thkECiOA7kJoy5.ve70BsLUAxVT9HsZuxcZbDi	9518449833	2025-09-16 17:17:18.06328
3	Armaan	armaan88503@gmail.com	$2b$10$FaeqrXElt2f4DW4losFwXueKUFATPq9KQFX4VHNfsMlKfQgmAM8Yi	9518449833	2025-09-17 12:34:59.844581
4	Kshitij	kshitij1123@gmail	$2b$10$/x01jbLUjiqdsWYbMX6AnOoKDyJuxsq3KmQ7R0SGgjPX/GzhFwEWu	7302230554	2025-09-17 18:53:25.799964
5	Nirmit	nirmit.jain2110@gmail.com	$2b$10$dyJl/nuvpT2QsSowGzJ7SecNXhiMkm4hSpxBQ50R5GnLJIA2GcqWW	75694662818	2025-09-22 23:54:41.751323
\.


--
-- Name: addresses_id_seq; Type: SEQUENCE SET; Schema: public; Owner: armaanbudhiraja
--

SELECT pg_catalog.setval('public.addresses_id_seq', 5, true);


--
-- Name: cart_items_id_seq; Type: SEQUENCE SET; Schema: public; Owner: armaanbudhiraja
--

SELECT pg_catalog.setval('public.cart_items_id_seq', 13, true);


--
-- Name: order_items_id_seq; Type: SEQUENCE SET; Schema: public; Owner: armaanbudhiraja
--

SELECT pg_catalog.setval('public.order_items_id_seq', 13, true);


--
-- Name: orders_id_seq; Type: SEQUENCE SET; Schema: public; Owner: armaanbudhiraja
--

SELECT pg_catalog.setval('public.orders_id_seq', 10, true);


--
-- Name: products_id_seq; Type: SEQUENCE SET; Schema: public; Owner: armaanbudhiraja
--

SELECT pg_catalog.setval('public.products_id_seq', 9, true);


--
-- Name: users_id_seq; Type: SEQUENCE SET; Schema: public; Owner: armaanbudhiraja
--

SELECT pg_catalog.setval('public.users_id_seq', 5, true);


--
-- Name: address addresses_pkey; Type: CONSTRAINT; Schema: public; Owner: armaanbudhiraja
--

ALTER TABLE ONLY public.address
    ADD CONSTRAINT addresses_pkey PRIMARY KEY (id);


--
-- Name: cart_items cart_items_pkey; Type: CONSTRAINT; Schema: public; Owner: armaanbudhiraja
--

ALTER TABLE ONLY public.cart_items
    ADD CONSTRAINT cart_items_pkey PRIMARY KEY (id);


--
-- Name: order_items order_items_pkey; Type: CONSTRAINT; Schema: public; Owner: armaanbudhiraja
--

ALTER TABLE ONLY public.order_items
    ADD CONSTRAINT order_items_pkey PRIMARY KEY (id);


--
-- Name: orders orders_pkey; Type: CONSTRAINT; Schema: public; Owner: armaanbudhiraja
--

ALTER TABLE ONLY public.orders
    ADD CONSTRAINT orders_pkey PRIMARY KEY (id);


--
-- Name: products products_pkey; Type: CONSTRAINT; Schema: public; Owner: armaanbudhiraja
--

ALTER TABLE ONLY public.products
    ADD CONSTRAINT products_pkey PRIMARY KEY (id);


--
-- Name: users users_email_key; Type: CONSTRAINT; Schema: public; Owner: armaanbudhiraja
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_email_key UNIQUE (email);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: armaanbudhiraja
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: address addresses_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: armaanbudhiraja
--

ALTER TABLE ONLY public.address
    ADD CONSTRAINT addresses_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: cart_items cart_items_product_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: armaanbudhiraja
--

ALTER TABLE ONLY public.cart_items
    ADD CONSTRAINT cart_items_product_id_fkey FOREIGN KEY (product_id) REFERENCES public.products(id);


--
-- Name: cart_items cart_items_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: armaanbudhiraja
--

ALTER TABLE ONLY public.cart_items
    ADD CONSTRAINT cart_items_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: order_items order_items_order_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: armaanbudhiraja
--

ALTER TABLE ONLY public.order_items
    ADD CONSTRAINT order_items_order_id_fkey FOREIGN KEY (order_id) REFERENCES public.orders(id) ON DELETE CASCADE;


--
-- Name: order_items order_items_product_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: armaanbudhiraja
--

ALTER TABLE ONLY public.order_items
    ADD CONSTRAINT order_items_product_id_fkey FOREIGN KEY (product_id) REFERENCES public.products(id);


--
-- Name: orders orders_address_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: armaanbudhiraja
--

ALTER TABLE ONLY public.orders
    ADD CONSTRAINT orders_address_id_fkey FOREIGN KEY (address_id) REFERENCES public.address(id);


--
-- Name: orders orders_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: armaanbudhiraja
--

ALTER TABLE ONLY public.orders
    ADD CONSTRAINT orders_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- PostgreSQL database dump complete
--

\unrestrict CHJ7LsaNFcDNNvUycG5v4FJFCShbAh9RGlgQ9u7gOGn2emrB2kJHRRqVAtWoTaa

