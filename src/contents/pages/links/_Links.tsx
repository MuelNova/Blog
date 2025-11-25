import React, { useState, useEffect } from "react";
import styles from "./_Links.module.scss"; // 导入 SCSS 模块

export interface LinkCardProps {
  icon?: string; // 图标链接
  link: string; // 链接地址
  linkText: string; // 链接的显示文本
  description?: string; // 链接的简介
}

const LinkCard: React.FC<LinkCardProps> = ({
  icon = "",
  link,
  linkText,
  description = "暂无介绍",
}) => {
  // 提取域名，并动态生成 Favicon 链接
  const getFaviconUrl = (url: string) => {
    try {
      const domain = new URL(url).origin; // 获取域名部分
      return `${domain}/favicon.ico`; // 返回 Favicon 链接
    } catch (error) {
      return ""; // 返回空字符串，如果 URL 无效
    }
  };

  const faviconUrl = icon ? icon : getFaviconUrl(link); // 如果有传入 icon 参数，则使用 icon 参数，否则动态生成 Favicon 链接

  const [imageSrc, setImageSrc] = useState(faviconUrl);

  useEffect(() => {
    setImageSrc(faviconUrl);
  }, [faviconUrl]);

  const useDefaultIcon = () => {
    setImageSrc(require("@site/src/static/img/404/" + Math.floor(Math.random()*20) + ".jpg").default);
  }

  return (
    <a
      href={link}
      target="_blank"
      rel="noopener noreferrer"
      className={styles.cardContainer} // 将整个卡片变成一个链接
    >
      <div className={styles.iconContainer}>
        <img src={imageSrc} alt={`${linkText} icon`} onError={useDefaultIcon} />
      </div>
      <div className={styles.textContainer}>
        <span className={styles.linkText}>{linkText}</span>
        <p className={styles.description}>{description}</p>
      </div>
    </a>
  );
};

export default LinkCard;
