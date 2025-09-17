import './Home.css'
import logo from '../images/logo.png'
import {Link} from "react-router-dom"
function Home(){
    return (
        <div className="Body">
            <div className="Navbar">               
                <h2 className='brand_name'>awesome sneakers</h2>
                <Link className='link' to='/home' >Home</Link>
                <Link className='link' to='/shop'>Shop</Link>
                <Link className='link' to='/cart'>Cart</Link>
                <Link className='link' to='/orders'>Orders</Link>
            </div>
            <div className="content">
                <img src={logo} alt="logo" className='logo' />
                <h2 className='title'>Your one-stop shop for awesome sneakers!</h2>
                <button className='shop_now'><Link className='link_shop' to='/shop'>Shop Now</Link></button>
            </div>
        </div>
    )
}

export default Home
