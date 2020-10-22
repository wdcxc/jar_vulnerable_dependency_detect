import os


def unzip_jar(jar_path):
    """解压jar包

    Args:
        jar_path ([type]): [description]

    Returns:
        [type]: [description]
    """
    jar_dir = os.path.abspath(os.path.dirname(jar_path))
    unzip_jar_dir = os.path.join(jar_dir, 'unzip_jar_dir')
    if not os.path.exists(unzip_jar_dir):
        os.makedirs(unzip_jar_dir)
    zfile = zipfile.ZipFile(jar_path, 'r')
    zfile.extractall(unzip_jar_dir)
    return unzip_jar_dir


def get_all_pom_xml(unzip_jar_dir):
    """获取解压后jar包中所有pox_xml文件

    Args:
        unzip_jar_dir ([type]): [description]

    Returns:
        [type]: [description]
    """
    maven_dir = os.path.join(unzip_jar_dir, 'META-INF', 'maven')
    if not os.path.exists(maven_dir):
        print('can not find maven dir')

    # g = os.walk(maven_dir)
    # for cur_path, dir_list, file_list in g:
    #     for f in file_list:
    #         if f.endswith('pom.xml'):
    #             pom_xml_file_list.append(os.path.join(cur_path, f))
    pom_xml_file_list = [os.path.join(cur_path, f) for cur_path, _, file_list in os.walk(
        maven_dir) for f in file_list if f.endswith('pom.xml')]
    # 验证文件是否存在
    # for f in pom_xml_file_list:
    #     if os.path.exists(f):
    #         print('pom file not exists')

    return pom_xml_file_list


def get_package_dependency_dict(pom_path):
    """获取pom对应包所有依赖

    Args:
        pom_path ([type]): [description]

    Returns:
        [type]: [description]
    """
    import xml.etree.ElementTree as ET
    tree = ET.ElementTree(file=pom_path)
    root = tree.getroot()
    package_dependency_dict = {}
    for elem in root.iter():
        tag = get_tag_name(elem)
        if tag == 'dependency':
            dependency_dict = {get_tag_name(
                child): child.text for child in elem}
            if dependency_dict['artifactId'] in package_dependency_dict:
                package_dependency_dict[dependency_dict['artifactId']].append(
                    dependency_dict)
            else:
                package_dependency_dict[dependency_dict['artifactId']] = [
                    dependency_dict]
    return package_dependency_dict


def get_tag_name(elem):
    return elem.tag.split('}')[-1]


def load_vulnerable_comp_excel(excel_path):
    """从excel加载漏洞组件及其版本

    Args:
        excel_path ([type]): [description]

    Returns:
        [type]: [description]
    """
    import xlrd
    wb = xlrd.open_workbook(filename=excel_path)
    # print(wb.sheet_names())
    sheet1 = wb.sheet_by_index(0)
    # print(sheet1.nrows, sheet1.ncols)
    nrows = sheet1.nrows
    vulnerable_comp_dict = {}
    for r_ind in range(1, nrows):
        row = sheet1.row_values(r_ind)
        comp_name = row[0].strip().lower()
        raw_version_list = str(row[1]).split(';')
        version_list = []
        for version in raw_version_list:
            if version.startswith('<='):
                version_list.append(('<=', version[2:]))
            elif version.startswith('<'):
                version_list.append(('<'), version[1:])
            elif '-' in version:
                version_list.append(('-', version))
            elif version.endswith('.x'):
                version_list.append(('x', version))
            else:
                version_list.append(('=', version))
        if not comp_name in vulnerable_comp_dict:
            vulnerable_comp_dict[comp_name] = version_list
        else:
            vulnerable_comp_dict[comp_name].append(version_list)
    return vulnerable_comp_dict


def compare(dependency_dict, vulnerable_comp_dict):
    """比对jar依赖和漏洞组件表

    Args:
        dependency_dict ([type]): [description]
        vulnerable_comp_dict ([type]): [description]

    Returns:
        [type]: [description]
    """
    compare_res = {}
    for package in dependency_dict:
        for comp, detail_list in dependency_dict[package].items():
            if comp in vulnerable_comp_dict:
                version_list = vulnerable_comp_dict[comp]
                for detail in detail_list:
                    comp_ver = detail['version']
                    comp_ver_list = comp_ver.split('.')

                    for typ, vul_ver in version_list:
                        is_vul = True
                        if typ == '-':
                            vul_ver_list = [v.split('.')
                                            for v in vul_ver.split('-')]
                        else:
                            vul_ver_list = vul_ver.split('.')

                        if typ == '<=':
                            for i, n in enumerate(vul_ver_list):
                                if n > comp_ver_list[i]:
                                    is_vul = False
                                    break
                        elif typ == '<':
                            for i, n in enumerate(vul_ver_list):
                                if n >= comp_ver_list[i]:
                                    is_vul = False
                                    break
                        elif typ == '-':
                            for i, n in enumerate(comp_ver_list):
                                if n < vul_ver_list[0][i] or n > vul_ver_list[1][i]:
                                    is_vul = False
                                    break
                        elif typ == 'x':
                            for i, n in enumerate(vul_ver_list[:-1]):
                                if n != comp_ver_list[i]:
                                    is_vul = False
                                    break
                        else:  # =
                            short_len = min(len(comp_ver), len(vul_ver))
                            if comp_ver[:short_len] != vul_ver[:short_len]:
                                is_vul = False
                        if is_vul:
                            compare_detail = {'package_version': comp_ver, 'vulnerable_version': vul_ver,
                                              'compare_type': typ, 'package_group': detail['groupId']}
                            if comp not in compare_res:
                                compare_res[comp] = [compare_detail]
                            else:
                                compare_res[comp].append(compare_detail)

    return compare_res


def detect(jar_path, vulnerable_comp_excel_path, res_save_path=None):
    """比对检测主体

    Args:
        jar_path ([type]): [description]
        vulnerable_comp_excel_path ([type]): [description]
        res_save_path ([type], optional): [description]. Defaults to None.

    Returns:
        [type]: [description]
    """
    # 解析jar获取依赖包信息
    import zipfile
    unzip_jar_dir = unzip_jar(jar_path)
    pom_xml_file_list = get_all_pom_xml(unzip_jar_dir)
    all_dependency_dict = {}
    for pom_path in pom_xml_file_list:
        package_name = pom_path[pom_path.find('maven')+6:]
        all_dependency_dict[package_name] = get_package_dependency_dict(
            pom_path)
    # print(all_dependency_dict)

    # 解析excel文件获取风险包信息
    vulnerable_comp_dict = load_vulnerable_comp_excel(
        vulnerable_comp_excel_path)
    # print(vulnerable_comp_dict)

    # 比对jar依赖包和风险包信息并生成结果
    compare_res = compare(all_dependency_dict, vulnerable_comp_dict)
    print_pretty_dict(compare_res)
    gene_compare_res_excel(compare_res, res_save_path)

    # 删除解压jar文件夹
    import shutil
    shutil.rmtree(unzip_jar_dir)

    return compare_res


def print_pretty_dict(d):
    import json
    print(json.dumps(d, indent=4, sort_keys=True))


def gene_compare_res_excel(compare_res, save_path=None):
    """生成检测结果excel

    Args:
        compare_res ([type]): [description]
        save_path ([type], optional): [description]. Defaults to None.
    """
    import xlwt
    wb = xlwt.Workbook()
    sheet1 = wb.add_sheet('jar包风险依赖检测结果')
    compare_res_list = convert_compare_res_to_list(compare_res)
    row_name_list = ['依赖包', 'jar包依赖版本', '有风险版本']
    for i, row_name in enumerate(row_name_list):
        sheet1.write(0, i, row_name)
    for r_ind in range(len(compare_res_list)):
        for c_ind in range(len(row_name_list)):
            sheet1.write(r_ind+1, c_ind, compare_res_list[r_ind][c_ind])
    wb.save(save_path if save_path else './data/对比检测结果.xlsx')


def convert_compare_res_to_list(compare_res):
    compare_res_list = []
    for package_name, detail_list in compare_res.items():
        for detail_dict in detail_list:
            # 拼接顺序参照 gene_compare_res_excel 中 excel 列名顺序
            compare_res_list.append(['.'.join([detail_dict['package_group'], package_name]),
                                     detail_dict['package_version'], detail_dict['vulnerable_version']])
    print(compare_res_list)
    return compare_res_list


detect('data/mybatis-3.5.6.jar', 'data/依赖漏洞.xlsx')
