import React, { useState } from 'react';

const HoverImage = ({ defaultSrc, hoverSrc, alt, ...props }) => {
    const [isHovering, setIsHovering] = useState(false);

    return (
        <img
            src={isHovering ? hoverSrc : defaultSrc}
            alt={alt}
            onMouseEnter={() => setIsHovering(true)}
            onMouseLeave={() => setIsHovering(false)}
            {...props}
        />
    );
};

export default HoverImage;
